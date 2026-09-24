//! 115 网盘驱动（对齐 Go 版 drivers/115 + SheltonZhu/115driver v1.3.5）
//!
//! - 授权：cookie（UID/CID/SEID[/KID]）
//! - 列目录：GET https://webapi.115.com/files（offset 分页，单页上限 1150）
//! - 下载：POST https://proapi.115.com/app/chrome/downurl?t={unix秒}
//!   form data 为 m115 加密的 {"pickcode": ...}，响应 data 为 m115 加密的直链映射
//! - 写操作：新建/重命名/移动/复制/删除走 webapi form 接口（对齐 115driver
//!   driver_op.go）；上传走 uploadinfo 预检 -> initupload.php（m115/ECDH 加密的
//!   sha1 闪传预检）-> 阿里云 OSS 直传（V1 签名 + callback，对齐 115driver
//!   upload.go 与 aliyun-oss-go-sdk）
//!
//! m115 加密：buf = key(16B) ++ data，三轮变换（xor/reverse/xor）后按
//! RSA-1024 公钥（E=0x10001）分块加密，再 base64。
//!
//! initupload.php 的 ECDH 加密（对齐 pkg/crypto/ec115）：
//! P-224 ECDH 协商 AES-128 密钥（请求体 = AES-CBC(PKCS7(lz4 前压缩)))
//! —— 见下方 ec115 段；本文件自实现 P-224 点运算（num-bigint）、AES-128
//! （FIPS-197）、LZ4 块解压与 CRC32-IEEE（依赖列表无对应 crate）。

use super::DownloadInfo;
use crate::config::Entry;
use base64::Engine;
use num_bigint::BigUint;
use rand::Rng;
use reqwest::{Client, Method};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

const API_FILE_LIST: &str = "https://webapi.115.com/files";
const API_DOWNLOAD: &str = "https://proapi.115.com/app/chrome/downurl";
const API_STATUS_CHECK: &str = "https://my.115.com/?ct=guide&ac=status";
const API_APP_VERSION: &str = "https://appversion.115.com/1/web/1.0/api/chrome";
const FALLBACK_APP_VER: &str = "35.6.0.3";
/// 单页目录上限（对齐 MaxDirPageLimit）
const MAX_PAGE_LIMIT: i64 = 1150;

// ---------- 写操作 / 上传 API（对齐 115driver driver_api.go） ----------

const API_DIR_ADD: &str = "https://webapi.115.com/files/add";
const API_FILE_DELETE: &str = "https://webapi.115.com/rb/delete";
const API_FILE_MOVE: &str = "https://webapi.115.com/files/move";
const API_FILE_COPY: &str = "https://webapi.115.com/files/copy";
const API_FILE_RENAME: &str = "https://webapi.115.com/files/batch_rename";
const API_UPLOAD_INFO: &str = "https://proapi.115.com/app/uploadinfo";
const API_UPLOAD_OSS_TOKEN: &str = "https://uplb.115.com/3.0/gettoken.php";
const API_UPLOAD_INIT: &str = "https://uplb.115.com/4.0/initupload.php";
/// OSS 双栈域名（对齐 OSSEndpoint）
const OSS_ENDPOINT: &str = "cn-shenzhen.oss.aliyuncs.com";
/// OSS 上传 UA（对齐 OSSUserAgent）
const OSS_UA: &str = "aliyun-sdk-android/2.9.1";
/// GenerateToken 盐（对齐 md5Salt）
const MD5_SALT: &str = "Qclm8MGWUv59TnrR0XPg";
/// ec115 crc 盐（对齐 crcSalt）
const EC115_CRC_SALT: &str = "^j>WD3Kr?J2gLFjD4W2y@";

const KB: u64 = 1024;
const MB: u64 = 1024 * KB;
const GB: u64 = 1024 * MB;

/// 上传元信息缓存（对齐 GetUploadInfo 返回的 UserID/Userkey/UploadMetaInfo）
#[derive(Debug, Clone)]
struct UploadMeta {
    user_id: i64,
    userkey: String,
    size_limit: i64,
}

pub struct Pan115 {
    http: Client,
    cookie: Mutex<String>,
    ua: Mutex<String>,
    upload_meta: Mutex<Option<UploadMeta>>,
}

// ---------- m115 加密（对齐 pkg/crypto/m115） ----------

const RSA_N_HEX: &str = "8686980c0f5a24c4b9d43020cd2c22703ff3f450756529058b1cf88f09b86021\
36477198a6e2683149659bd122c33592fdb5ad47944ad1ea4d36c6b172aad633\
8c3bb6ac6227502d010993ac967d1aef00f0c8e038de2e4d3bc2ec368af2e9f1\
0a6f1eda4f7262f136420c07c331b871bf139f74f3010e3c4fe57df3afb71683";
const RSA_E: u32 = 0x10001;
const KEY_LEN: usize = 128;

const XOR_KEY_SEED: [u8; 144] = [
    0xf0, 0xe5, 0x69, 0xae, 0xbf, 0xdc, 0xbf, 0x8a, 0x1a, 0x45, 0xe8, 0xbe, 0x7d, 0xa6, 0x73, 0xb8,
    0xde, 0x8f, 0xe7, 0xc4, 0x45, 0xda, 0x86, 0xc4, 0x9b, 0x64, 0x8b, 0x14, 0x6a, 0xb4, 0xf1, 0xaa,
    0x38, 0x01, 0x35, 0x9e, 0x26, 0x69, 0x2c, 0x86, 0x00, 0x6b, 0x4f, 0xa5, 0x36, 0x34, 0x62, 0xa6,
    0x2a, 0x96, 0x68, 0x18, 0xf2, 0x4a, 0xfd, 0xbd, 0x6b, 0x97, 0x8f, 0x4d, 0x8f, 0x89, 0x13, 0xb7,
    0x6c, 0x8e, 0x93, 0xed, 0x0e, 0x0d, 0x48, 0x3e, 0xd7, 0x2f, 0x88, 0xd8, 0xfe, 0xfe, 0x7e, 0x86,
    0x50, 0x95, 0x4f, 0xd1, 0xeb, 0x83, 0x26, 0x34, 0xdb, 0x66, 0x7b, 0x9c, 0x7e, 0x9d, 0x7a, 0x81,
    0x32, 0xea, 0xb6, 0x33, 0xde, 0x3a, 0xa9, 0x59, 0x34, 0x66, 0x3b, 0xaa, 0xba, 0x81, 0x60, 0x48,
    0xb9, 0xd5, 0x81, 0x9c, 0xf8, 0x6c, 0x84, 0x77, 0xff, 0x54, 0x78, 0x26, 0x5f, 0xbe, 0xe8, 0x1e,
    0x36, 0x9f, 0x34, 0x80, 0x5c, 0x45, 0x2c, 0x9b, 0x76, 0xd5, 0x1b, 0x8f, 0xcc, 0xc3, 0xb8, 0xf5,
];

const XOR_CLIENT_KEY: [u8; 12] = [
    0x78, 0x06, 0xad, 0x4c, 0x33, 0x86, 0x5d, 0x18, 0x4c, 0x01, 0x3f, 0x46,
];

fn rsa_n() -> &'static BigUint {
    static N: OnceLock<BigUint> = OnceLock::new();
    N.get_or_init(|| BigUint::from_bytes_be(&hex_decode(RSA_N_HEX).unwrap()))
}

fn rsa_e() -> BigUint {
    BigUint::from(RSA_E)
}

/// RSA-1024 PKCS#1 v1.5 type-2 分块加密（对齐 rsaEncrypt）
fn rsa_encrypt(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity((input.len() / (KEY_LEN - 11) + 1) * KEY_LEN);
    let mut input = input;
    while !input.is_empty() {
        let slice_size = (KEY_LEN - 11).min(input.len());
        let slice = &input[..slice_size];
        input = &input[slice_size..];
        // PKCS#1 padding: 0x00 0x02 + non-zero pad + 0x00 + data
        let pad_size = KEY_LEN - slice.len() - 3;
        let mut buf = vec![0u8; KEY_LEN];
        buf[0] = 0;
        buf[1] = 2;
        for b in buf[2..2 + pad_size].iter_mut() {
            // 简单伪随机即可（服务端不校验 padding 内容）
            *b = (pseudo_random_byte() % 0xff) + 0x01;
        }
        buf[2 + pad_size] = 0;
        buf[3 + pad_size..].copy_from_slice(slice);
        let msg = BigUint::from_bytes_be(&buf);
        let ret = msg.modpow(&rsa_e(), rsa_n());
        let ret_bytes = ret.to_bytes_be();
        // 前导补零至 128 字节
        out.extend(std::iter::repeat_n(0, KEY_LEN - ret_bytes.len()));
        out.extend_from_slice(&ret_bytes);
    }
    out
}

/// RSA 公钥指数"解密"（对齐 rsaDecrypt：服务端以私钥方向处理，两侧同用 E）
fn rsa_decrypt(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut input = input;
    while !input.is_empty() {
        let slice_size = KEY_LEN.min(input.len());
        let slice = &input[..slice_size];
        input = &input[slice_size..];
        let msg = BigUint::from_bytes_be(slice);
        let ret = msg.modpow(&rsa_e(), rsa_n());
        let ret = ret.to_bytes_be();
        // unpad：跳过前导零，找第一个 0 字节后的内容
        let mut i = 0;
        while i < ret.len() && ret[i] == 0 {
            i += 1;
        }
        // 此时 i 指向 0x02，继续找分隔 0
        while i < ret.len() {
            if ret[i] == 0 {
                out.extend_from_slice(&ret[i + 1..]);
                break;
            }
            i += 1;
        }
    }
    out
}

fn pseudo_random_byte() -> u8 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    (n ^ (n >> 8) ^ std::process::id()) as u8
}

fn xor_derive_key(seed: &[u8], size: usize) -> Vec<u8> {
    let mut key = vec![0u8; size];
    for i in 0..size {
        // Go 版 (a + b) & 0xff 语义：u8 加法回绕
        key[i] = seed[i].wrapping_add(XOR_KEY_SEED[size * i]);
        key[i] ^= XOR_KEY_SEED[size * (size - i - 1)];
    }
    key
}

fn xor_transform(data: &mut [u8], key: &[u8]) {
    let data_size = data.len();
    let key_size = key.len();
    let mode = data_size % 4;
    for i in 0..mode {
        data[i] ^= key[i % key_size];
    }
    for i in mode..data_size {
        data[i] ^= key[(i - mode) % key_size];
    }
}

fn reverse_bytes(data: &mut [u8]) {
    data.reverse();
}

/// m115 加密（对齐 Encode）
fn m115_encode(input: &[u8], key: &[u8; 16]) -> String {
    let mut buf = Vec::with_capacity(16 + input.len());
    buf.extend_from_slice(key);
    buf.extend_from_slice(input);
    let (head, data) = buf.split_at_mut(16);
    xor_transform(data, &xor_derive_key(head, 4));
    reverse_bytes(data);
    xor_transform(data, &XOR_CLIENT_KEY);
    base64::engine::general_purpose::STANDARD.encode(rsa_encrypt(&buf))
}

/// m115 解密（对齐 Decode）
fn m115_decode(input: &str, key: &[u8; 16]) -> Result<Vec<u8>, String> {
    let data = base64::engine::general_purpose::STANDARD
        .decode(input)
        .map_err(|e| format!("m115 base64 解码失败: {e}"))?;
    let mut data = rsa_decrypt(&data);
    if data.len() < 16 {
        return Err("m115 解密数据过短".into());
    }
    let head: [u8; 16] = data[..16].try_into().unwrap();
    let mut output = data.split_off(16);
    xor_transform(&mut output, &xor_derive_key(&head, 12));
    reverse_bytes(&mut output);
    xor_transform(&mut output, &xor_derive_key(key, 4));
    Ok(output)
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("hex 长度非法".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn random_key() -> [u8; 16] {
    let mut key = [0u8; 16];
    let u1 = uuid::Uuid::new_v4();
    let u2 = uuid::Uuid::new_v4();
    key[..8].copy_from_slice(&u1.as_bytes()[..8]);
    key[8..].copy_from_slice(&u2.as_bytes()[..8]);
    key
}

// ---------- 工具 ----------

fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Value 强转字符串（115 接口数字/字符串混用）
fn coerce_str(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

/// "2024-01-02 15:04"（东八区）-> unix 毫秒
fn parse_115_time(s: &str) -> Option<i64> {
    let num = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    if s.len() < 16 {
        return None;
    }
    let y = num(0..4)?;
    let mo = num(5..7)?;
    let d = num(8..10)?;
    let h = num(11..13)?;
    let mi = num(14..16)?;
    let days = days_from_civil(y, mo, d);
    Some((days * 86400 + h * 3600 + mi * 60 - 8 * 3600) * 1000)
}

// 日期换算统一走 drivers/timeutil（原为本地副本）
use super::timeutil::{civil_from_days, days_from_civil, weekday_short_utc};

impl Pan115 {
    pub fn new(cookie: String) -> Self {
        Pan115 {
            http: Client::new(),
            cookie: Mutex::new(cookie),
            ua: Mutex::new(format!("Mozilla/5.0 115Browser/{FALLBACK_APP_VER}")),
            upload_meta: Mutex::new(None),
        }
    }

    fn cookie(&self) -> String {
        self.cookie.lock().unwrap().clone()
    }

    fn ua(&self) -> String {
        self.ua.lock().unwrap().clone()
    }

    /// 对齐 OpenList initAppVer：拉取官方 web 版本号拼 UA
    async fn init_app_ver(&self) {
        let ver = match self.http.get(API_APP_VERSION).send().await {
            Ok(resp) => resp.json::<Value>().await.ok(),
            Err(_) => None,
        }
        .and_then(|v| {
            v.pointer("/data/win/version_code")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string())
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| FALLBACK_APP_VER.to_string());
        *self.ua.lock().unwrap() = format!("Mozilla/5.0 115Browser/{ver}");
    }

    /// 统一请求入口：带 cookie + 115Browser UA
    async fn request(
        &self,
        method: Method,
        url: &str,
        query: Option<&[(String, String)]>,
        form: Option<&[(&str, String)]>,
    ) -> Result<Value, String> {
        let mut req = self
            .http
            .request(method, url)
            .header("Cookie", self.cookie())
            .header("User-Agent", self.ua());
        if let Some(q) = query {
            req = req.query(q);
        }
        if let Some(f) = form {
            req = req.form(f);
        }
        let resp = req.send().await.map_err(|e| format!("请求失败: {e}"))?;
        let status = resp.status();
        let v: Value = resp
            .json()
            .await
            .map_err(|e| format!("响应解析失败: {e}"))?;
        if status.as_u16() >= 400 {
            return Err(format!("115 接口 HTTP {status}"));
        }
        // 对齐 BasicResp 检查：state 为 false 即出错
        if v.get("state") == Some(&Value::Bool(false)) {
            let msg = v
                .get("error")
                .or_else(|| v.get("msg"))
                .or_else(|| v.get("message"))
                .and_then(|m| m.as_str())
                .unwrap_or("unknown");
            let errno = coerce_str(v.get("errno"));
            return Err(format!("115 接口错误(errno={errno}): {msg}"));
        }
        Ok(v)
    }

    /// 对齐 login()：校验 cookie 格式并检查登录状态
    pub async fn validate(&self) -> Result<(), String> {
        // cookie 至少要包含 UID/CID/SEID（对齐 Credential.FromCookie）
        let cookie = self.cookie();
        let mut uid = String::new();
        let mut cid = String::new();
        let mut seid = String::new();
        for item in cookie.split(';') {
            let item = item.trim();
            let Some((k, v)) = item.split_once('=') else {
                continue;
            };
            match k.trim().to_uppercase().as_str() {
                "UID" => uid = v.to_string(),
                "CID" => cid = v.to_string(),
                "SEID" => seid = v.to_string(),
                _ => {}
            }
        }
        if uid.is_empty() || cid.is_empty() || seid.is_empty() {
            return Err("115 cookie 无效：缺少 UID/CID/SEID".into());
        }
        self.init_app_ver().await;
        // 对齐 CookieCheck：GET status，state=false 即 cookie 失效
        let url = format!("{API_STATUS_CHECK}&_={}", unix_millis());
        let v = self.request(Method::GET, &url, None, None).await?;
        if v.get("state") != Some(&Value::Bool(true)) {
            return Err("115 cookie 已失效".into());
        }
        Ok(())
    }

    /// 对齐 ListWithLimit + File.from：offset 分页
    pub async fn list(&self, dir_id: &str) -> Result<Vec<Entry>, String> {
        let dir_id = if dir_id.is_empty() { "0" } else { dir_id };
        let mut files = Vec::new();
        let mut offset: i64 = 0;
        let limit: i64 = MAX_PAGE_LIMIT;
        loop {
            let query = vec![
                ("aid".into(), "1".into()),
                ("cid".into(), dir_id.to_string()),
                ("o".into(), "user_ptime".into()),
                ("asc".into(), "0".into()),
                ("offset".into(), offset.to_string()),
                ("show_dir".into(), "1".into()),
                ("limit".into(), limit.to_string()),
                ("snap".into(), "0".into()),
                ("natsort".into(), "0".into()),
                ("record_open_time".into(), "1".into()),
                ("count_folders".into(), "1".into()),
                ("format".into(), "json".into()),
                ("fc_mix".into(), "0".into()),
            ];
            let resp = self
                .request(Method::GET, API_FILE_LIST, Some(&query), None)
                .await?;
            let list = resp
                .get("data")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            if list.is_empty() {
                break;
            }
            for f in &list {
                let file_id = coerce_str(f.get("fid"));
                let name = coerce_str(f.get("n"));
                let pick_code = coerce_str(f.get("pc"));
                let (entry_fid, is_dir) = if file_id.is_empty() {
                    // 目录：fid 为空，自身 id 在 cid
                    (coerce_str(f.get("cid")), true)
                } else {
                    (file_id, false)
                };
                let updated_at = if is_dir {
                    // 目录 t 为 unix 秒字符串
                    coerce_str(f.get("t")).parse::<i64>().ok().map(|s| s * 1000)
                } else {
                    // 文件 t 为 "YYYY-MM-DD HH:MM" 东八区字符串
                    coerce_str(f.get("t"))
                        .as_str()
                        .parse::<String>()
                        .ok()
                        .and_then(|_| parse_115_time(&coerce_str(f.get("t"))))
                };
                files.push(Entry {
                    fid: entry_fid,
                    name,
                    size: f.get("s").and_then(|v| v.as_u64()).unwrap_or(0),
                    is_dir,
                    updated_at,
                    etag: None,
                    s3_key_flag: None,
                    file_type: None,
                    // 下载需要 pick_code
                    extra: Some(json!({ "pc": pick_code })),
                });
            }
            let count = resp.get("count").and_then(|v| v.as_i64()).unwrap_or(0);
            offset += limit;
            if offset >= count {
                break;
            }
        }
        Ok(files)
    }

    /// 对齐 DownloadWithUA：m115 加密 pickcode 请求直链
    ///
    /// Go 版关键行为（对齐 buildDownloadHeaders）：
    /// 1. 取链请求本身带 Cookie + User-Agent
    /// 2. 115 服务器会在响应里下发新 Cookie（Set-Cookie），需合并进 info.Header
    /// 3. 下载时必须同时带上这些 Cookie + 相同的 UA，否则 CDN 返回 403
    pub async fn download(&self, e: &Entry) -> Result<DownloadInfo, String> {
        let pick_code = e
            .extra
            .as_ref()
            .and_then(|x| x.get("pc"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if pick_code.is_empty() {
            return Err("缺少 pick_code（请从文件列表发起下载）".into());
        }
        let key = random_key();
        let params = json!({ "pickcode": pick_code }).to_string();
        let encoded = m115_encode(params.as_bytes(), &key);
        let url = format!("{API_DOWNLOAD}?t={}", unix_secs());

        // 直接用 reqwest 发送，需要拿到完整响应头（含 Set-Cookie）
        // 对齐 Go 版 sentRequestHeaders + buildDownloadHeaders
        let ua = self.ua();
        let cookie = self.cookie();
        let raw_resp = self
            .http
            .request(Method::POST, &url)
            .header("Cookie", &cookie)
            .header("User-Agent", &ua)
            .form(&[("data", encoded)])
            .send()
            .await
            .map_err(|e| format!("请求失败: {e}"))?;

        // 收集响应里的 Set-Cookie，合并进下载头（对齐 buildDownloadHeaders）
        let mut extra_cookies: Vec<String> = raw_resp
            .headers()
            .get_all(reqwest::header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .map(|s| {
                // 只取 name=value 部分，去掉 Path/Domain/Expires 等属性
                s.split(';').next().unwrap_or("").trim().to_string()
            })
            .filter(|s| !s.is_empty())
            .collect();

        let v: Value = raw_resp
            .json()
            .await
            .map_err(|e| format!("响应解析失败: {e}"))?;

        if v.get("state") == Some(&Value::Bool(false)) {
            let msg = v
                .get("error")
                .or_else(|| v.get("msg"))
                .or_else(|| v.get("message"))
                .and_then(|m| m.as_str())
                .unwrap_or("unknown");
            let errno = coerce_str(v.get("errno"));
            return Err(format!("115 接口错误(errno={errno}): {msg}"));
        }

        let encoded_data = match v.get("data") {
            Some(Value::String(s)) => s.clone(),
            _ => return Err("115 未返回有效的下载数据（可能需要验证或 cookie 失效）".into()),
        };
        let decoded = m115_decode(&encoded_data, &key)?;
        let dv: Value =
            serde_json::from_slice(&decoded).map_err(|e| format!("m115 解密结果解析失败: {e}"))?;
        // 响应结构：{ "<file_id>": { "url": { "url": "..." } } }
        let dl_url = dv
            .as_object()
            .and_then(|m| m.values().next())
            .and_then(|info| info.pointer("/url/url"))
            .and_then(|u| u.as_str())
            .unwrap_or("")
            .to_string();
        if dl_url.is_empty() {
            return Err("115 未返回下载直链".into());
        }

        // 构建下载请求头（对齐 Go buildDownloadHeaders）：
        // 取链时发送的 Cookie（账号 cookie）+ 响应 Set-Cookie + 相同的 UA
        let mut merged_cookies: Vec<String> = cookie
            .split(';')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        merged_cookies.append(&mut extra_cookies);
        let merged_cookie_str = merged_cookies.join("; ");

        Ok(DownloadInfo {
            url: dl_url,
            headers: vec![
                ("User-Agent".into(), ua),
                ("Cookie".into(), merged_cookie_str),
            ],
            proxy: true,
            local_path: None,
        })
    }
}

// ============================================================
// 写操作 & 上传（对齐 Go 版 drivers/115 + 115driver upload.go）
// ============================================================

// ---------- 通用哈希 / 编码辅助 ----------

fn sha1_hex(data: &[u8]) -> String {
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(data);
    hex::encode(h.finalize())
}

fn md5_hex(data: &[u8]) -> String {
    use md5::{Digest, Md5};
    let mut h = Md5::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// HMAC-SHA1（OSS V1 签名用；依赖无 hmac crate，手写 RFC 2104）
fn hmac_sha1(key: &[u8], msg: &[u8]) -> Vec<u8> {
    use sha1::{Digest, Sha1};
    const BLOCK: usize = 64;
    let mut k = key.to_vec();
    if k.len() > BLOCK {
        let mut h = Sha1::new();
        h.update(&k);
        k = h.finalize().to_vec();
    }
    k.resize(BLOCK, 0);
    let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    let mut inner = Sha1::new();
    inner.update(ipad);
    inner.update(msg);
    let inner_sum = inner.finalize();
    let mut outer = Sha1::new();
    outer.update(opad);
    outer.update(inner_sum);
    outer.finalize().to_vec()
}

/// Go url.QueryEscape：空格 -> '+'，字母数字与 -_.~ 不转义
fn go_query_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// URL path 段转义（保留 '/'，空格 -> %20）
fn escape_url_path(s: &str) -> String {
    s.split('/')
        .map(|seg| {
            let mut out = String::with_capacity(seg.len());
            for &b in seg.as_bytes() {
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

/// RFC1123 GMT 时间（OSS Date 头，对齐 Go http.TimeFormat）
fn gmt_http_date() -> String {
    const MON: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let secs = unix_secs() as i64;
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} GMT",
        weekday_short_utc(days),
        d,
        MON[(m - 1) as usize],
        y,
        h,
        mi,
        s
    )
}

// ---------- 临时文件（边写边算 full sha1 + 前 128KB sha1） ----------

struct TempFileGuard(PathBuf);

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn temp_file_path() -> PathBuf {
    std::env::temp_dir().join(format!("openlist-rs-115-{}", uuid::Uuid::new_v4()))
}

/// 把上传流落到临时文件；返回 (实际大小, 整文件 sha1 hex, 前 min(size,128KB) 的 sha1 hex)
/// 对齐 Go Put 的 fullHash + PreHash
async fn spool_and_sha1(
    mut reader: std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send>>,
    path: &PathBuf,
) -> Result<(u64, String, String), String> {
    use sha1::{Digest, Sha1};
    let mut f = tokio::fs::File::create(path)
        .await
        .map_err(|e| format!("115 创建临时文件失败: {e}"))?;
    let mut full = Sha1::new();
    let mut pre = Sha1::new();
    let mut pre_left: u64 = 128 * KB;
    let mut buf = vec![0u8; (256 * KB) as usize];
    let mut total: u64 = 0;
    loop {
        let n = reader
            .read(&mut buf)
            .await
            .map_err(|e| format!("115 读取上传流失败: {e}"))?;
        if n == 0 {
            break;
        }
        f.write_all(&buf[..n])
            .await
            .map_err(|e| format!("115 写入临时文件失败: {e}"))?;
        full.update(&buf[..n]);
        if pre_left > 0 {
            let take = (n as u64).min(pre_left) as usize;
            pre.update(&buf[..take]);
            pre_left -= take as u64;
        }
        total += n as u64;
    }
    f.flush()
        .await
        .map_err(|e| format!("115 临时文件落盘失败: {e}"))?;
    let full_hex = hex::encode(full.finalize());
    let pre_hex = if pre_left > 0 {
        // 文件不足 128KB：pre 哈希与 full 相同
        full_hex.clone()
    } else {
        hex::encode(pre.finalize())
    };
    Ok((total, full_hex, pre_hex))
}

/// 从临时文件读取区间 [start, end]（闭区间）并返回大写 sha1
/// 对齐 UploadDigestRange(stream, sign_check)
async fn sha1_range_upper(path: &Path, start: u64, end: u64) -> Result<String, String> {
    use sha1::{Digest, Sha1};
    let mut f = tokio::fs::File::open(path)
        .await
        .map_err(|e| format!("115 打开临时文件失败: {e}"))?;
    f.seek(std::io::SeekFrom::Start(start))
        .await
        .map_err(|e| format!("115 临时文件 seek 失败: {e}"))?;
    let len = (end - start + 1) as usize;
    let mut h = Sha1::new();
    let mut left = len;
    let mut buf = vec![0u8; (256 * KB) as usize];
    while left > 0 {
        let want = left.min(buf.len());
        let n = f
            .read(&mut buf[..want])
            .await
            .map_err(|e| format!("115 读取临时文件失败: {e}"))?;
        if n == 0 {
            return Err("115 读取临时文件区间失败：数据不足".into());
        }
        h.update(&buf[..n]);
        left -= n;
    }
    Ok(hex::encode(h.finalize()).to_uppercase())
}

// ---------- AES-128（FIPS-197 自实现；S-box 运行时由 GF(2^8) 求逆 + 仿射变换生成） ----------

struct AesTables {
    sbox: [u8; 256],
    inv_sbox: [u8; 256],
}

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            p ^= a;
        }
        a = xtime(a);
        b >>= 1;
    }
    p
}

fn xtime(a: u8) -> u8 {
    (a << 1) ^ if a & 0x80 != 0 { 0x1b } else { 0 }
}

fn aes_tables() -> &'static AesTables {
    static T: OnceLock<AesTables> = OnceLock::new();
    T.get_or_init(|| {
        // GF(2^8) 逆元表
        let mut inv = [0u8; 256];
        for a in 1..=255u8 {
            for b in 1..=255u8 {
                if gf_mul(a, b) == 1 {
                    inv[a as usize] = b;
                    break;
                }
            }
        }
        let mut sbox = [0u8; 256];
        for x in 0..256usize {
            let b = inv[x];
            sbox[x] = b
                ^ b.rotate_left(1)
                ^ b.rotate_left(2)
                ^ b.rotate_left(3)
                ^ b.rotate_left(4)
                ^ 0x63;
        }
        let mut inv_sbox = [0u8; 256];
        for (i, &s) in sbox.iter().enumerate() {
            inv_sbox[s as usize] = i as u8;
        }
        AesTables { sbox, inv_sbox }
    })
}

struct Aes128 {
    round_keys: [[u8; 16]; 11],
}

impl Aes128 {
    fn new(key: &[u8; 16]) -> Aes128 {
        let t = aes_tables();
        let mut w = [[0u8; 4]; 44];
        for i in 0..4 {
            w[i].copy_from_slice(&key[4 * i..4 * i + 4]);
        }
        let mut rc = 1u8;
        for i in 4..44 {
            let mut temp = w[i - 1];
            if i % 4 == 0 {
                // SubWord(RotWord(temp)) ^ Rcon
                temp = [
                    t.sbox[temp[1] as usize],
                    t.sbox[temp[2] as usize],
                    t.sbox[temp[3] as usize],
                    t.sbox[temp[0] as usize],
                ];
                temp[0] ^= rc;
                rc = gf_mul(rc, 2);
            }
            for j in 0..4 {
                w[i][j] = w[i - 4][j] ^ temp[j];
            }
        }
        let mut round_keys = [[0u8; 16]; 11];
        for r in 0..11 {
            for c in 0..4 {
                round_keys[r][4 * c..4 * c + 4].copy_from_slice(&w[4 * r + c]);
            }
        }
        Aes128 { round_keys }
    }

    fn add_round_key(state: &mut [u8; 16], rk: &[u8; 16]) {
        for i in 0..16 {
            state[i] ^= rk[i];
        }
    }

    fn shift_rows(state: &mut [u8; 16]) {
        let src = *state;
        for c in 0..4 {
            for r in 0..4 {
                state[4 * c + r] = src[4 * ((c + r) % 4) + r];
            }
        }
    }

    fn inv_shift_rows(state: &mut [u8; 16]) {
        let src = *state;
        for c in 0..4 {
            for r in 0..4 {
                state[4 * ((c + r) % 4) + r] = src[4 * c + r];
            }
        }
    }

    fn mix_columns(state: &mut [u8; 16]) {
        for c in 0..4 {
            let o = 4 * c;
            let col = [state[o], state[o + 1], state[o + 2], state[o + 3]];
            state[o] = gf_mul(col[0], 2) ^ gf_mul(col[1], 3) ^ col[2] ^ col[3];
            state[o + 1] = col[0] ^ gf_mul(col[1], 2) ^ gf_mul(col[2], 3) ^ col[3];
            state[o + 2] = col[0] ^ col[1] ^ gf_mul(col[2], 2) ^ gf_mul(col[3], 3);
            state[o + 3] = gf_mul(col[0], 3) ^ col[1] ^ col[2] ^ gf_mul(col[3], 2);
        }
    }

    fn inv_mix_columns(state: &mut [u8; 16]) {
        for c in 0..4 {
            let o = 4 * c;
            let col = [state[o], state[o + 1], state[o + 2], state[o + 3]];
            state[o] =
                gf_mul(col[0], 14) ^ gf_mul(col[1], 11) ^ gf_mul(col[2], 13) ^ gf_mul(col[3], 9);
            state[o + 1] =
                gf_mul(col[0], 9) ^ gf_mul(col[1], 14) ^ gf_mul(col[2], 11) ^ gf_mul(col[3], 13);
            state[o + 2] =
                gf_mul(col[0], 13) ^ gf_mul(col[1], 9) ^ gf_mul(col[2], 14) ^ gf_mul(col[3], 11);
            state[o + 3] =
                gf_mul(col[0], 11) ^ gf_mul(col[1], 13) ^ gf_mul(col[2], 9) ^ gf_mul(col[3], 14);
        }
    }

    fn encrypt_block(&self, state: &mut [u8; 16]) {
        let t = aes_tables();
        Self::add_round_key(state, &self.round_keys[0]);
        for round in 1..10 {
            for b in state.iter_mut() {
                *b = t.sbox[*b as usize];
            }
            Self::shift_rows(state);
            Self::mix_columns(state);
            Self::add_round_key(state, &self.round_keys[round]);
        }
        for b in state.iter_mut() {
            *b = t.sbox[*b as usize];
        }
        Self::shift_rows(state);
        Self::add_round_key(state, &self.round_keys[10]);
    }

    fn decrypt_block(&self, state: &mut [u8; 16]) {
        let t = aes_tables();
        Self::add_round_key(state, &self.round_keys[10]);
        for round in (1..10).rev() {
            Self::inv_shift_rows(state);
            for b in state.iter_mut() {
                *b = t.inv_sbox[*b as usize];
            }
            Self::add_round_key(state, &self.round_keys[round]);
            Self::inv_mix_columns(state);
        }
        Self::inv_shift_rows(state);
        for b in state.iter_mut() {
            *b = t.inv_sbox[*b as usize];
        }
        Self::add_round_key(state, &self.round_keys[0]);
    }
}

// ---------- CRC32-IEEE（ec115 EncodeToken 用） ----------

fn crc32_ieee(data: &[u8]) -> u32 {
    static TABLE: OnceLock<[u32; 256]> = OnceLock::new();
    let table = TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for i in 0..256u32 {
            let mut c = i;
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    0xEDB8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
            }
            t[i as usize] = c;
        }
        t
    });
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc = (crc >> 8) ^ table[((crc ^ b as u32) & 0xFF) as usize];
    }
    !crc
}

// ---------- LZ4 块解压（ec115 Decrypt 用，对齐 pierrec/lz4 UncompressBlock） ----------

fn lz4_decompress(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut out: Vec<u8> = Vec::with_capacity(0x2000);
    let mut i = 0usize;
    while i < input.len() {
        let token = input[i];
        i += 1;
        // 字面量长度
        let mut lit_len = (token >> 4) as usize;
        if lit_len == 15 {
            loop {
                if i >= input.len() {
                    return Err("115 ec115: lz4 字面量长度数据不完整".into());
                }
                let b = input[i];
                i += 1;
                lit_len += b as usize;
                if b != 255 {
                    break;
                }
            }
        }
        if i + lit_len > input.len() {
            return Err("115 ec115: lz4 字面量越界".into());
        }
        out.extend_from_slice(&input[i..i + lit_len]);
        i += lit_len;
        if i >= input.len() {
            break; // 最后一个 token 只含字面量
        }
        // 匹配偏移（小端 2 字节）
        if i + 2 > input.len() {
            return Err("115 ec115: lz4 偏移数据不完整".into());
        }
        let offset = u16::from_le_bytes([input[i], input[i + 1]]) as usize;
        i += 2;
        if offset == 0 || offset > out.len() {
            return Err("115 ec115: lz4 匹配偏移非法".into());
        }
        // 匹配长度
        let mut match_len = ((token & 0x0f) as usize) + 4;
        loop {
            if i >= input.len() {
                return Err("115 ec115: lz4 匹配长度数据不完整".into());
            }
            let b = input[i];
            i += 1;
            match_len += b as usize;
            if b != 255 {
                break;
            }
        }
        // 逐字节拷贝（允许重叠）
        for pos in (out.len() - offset..).take(match_len) {
            let b = out[pos];
            out.push(b);
        }
    }
    Ok(out)
}

// ---------- P-224 ECDH（ec115 NewEcdhCipher 用；num-bigint 实现仿射点运算） ----------

fn p224_p() -> BigUint {
    BigUint::from_bytes_be(
        &hex::decode("ffffffffffffffffffffffffffffffff000000000000000000000001").unwrap(),
    )
}

fn p224_n() -> BigUint {
    BigUint::from_bytes_be(
        &hex::decode("ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d").unwrap(),
    )
}

/// secp224r1 基点
fn p224_g() -> (BigUint, BigUint) {
    let gx = BigUint::from_bytes_be(
        &hex::decode("b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21").unwrap(),
    );
    let gy = BigUint::from_bytes_be(
        &hex::decode("bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34").unwrap(),
    );
    (gx, gy)
}

/// 远端 115 固定公钥（对齐 remotePubKey：X ++ Y，各 28 字节）
const EC115_REMOTE_PUB: [u8; 56] = [
    0x57, 0xA2, 0x92, 0x57, 0xCD, 0x23, 0x20, 0xE5, 0xD6, 0xD1, 0x43, 0x32, 0x2F, 0xA4, 0xBB, 0x8A,
    0x3C, 0xF9, 0xD3, 0xCC, 0x62, 0x3E, 0xF5, 0xED, 0xAC, 0x62, 0xB7, 0x67, 0x8A, 0x89, 0xC9, 0x1A,
    0x83, 0xBA, 0x80, 0x0D, 0x61, 0x29, 0xF5, 0x22, 0xD0, 0x34, 0xC8, 0x95, 0xDD, 0x24, 0x65, 0x24,
    0x3A, 0xDD, 0xC2, 0x50, 0x95, 0x3B, 0xEE, 0xBA,
];

type EcPoint = Option<(BigUint, BigUint)>;

/// 模减 (a - b) mod m（a、b 均已约简到 [0, m)）
fn mod_sub(a: &BigUint, b: &BigUint, m: &BigUint) -> BigUint {
    if a >= b {
        a - b
    } else {
        (a + m - b) % m
    }
}

/// 模逆 x^(m-2) mod m（m 为素数）
fn mod_inv(x: &BigUint, m: &BigUint) -> BigUint {
    let e = m - BigUint::from(2u32);
    x.modpow(&e, m)
}

fn ec_add(p: &EcPoint, q: &EcPoint) -> EcPoint {
    let (x1, y1) = p.as_ref()?;
    let (x2, y2) = q.as_ref()?;
    let m = p224_p();
    if x1 == x2 {
        if y1 == y2 {
            return ec_double(x1, y1);
        }
        return None; // 互逆 -> 无穷远点
    }
    let dx = mod_sub(x2, x1, &m);
    let dy = mod_sub(y2, y1, &m);
    let lambda = (dy * mod_inv(&dx, &m)) % &m;
    let sq = (&lambda * &lambda) % &m;
    let x3 = mod_sub(&mod_sub(&sq, x1, &m), x2, &m);
    let y3 = mod_sub(&((lambda * mod_sub(x1, &x3, &m)) % &m), y1, &m);
    Some((x3, y3))
}

fn ec_double(x: &BigUint, y: &BigUint) -> EcPoint {
    let m = p224_p();
    if *y == BigUint::from(0u32) {
        return None;
    }
    // lambda = (3x^2 + a) / (2y)，a = -3 (mod p)
    let num = (((x * x) % &m * 3u32) + &m - BigUint::from(3u32)) % &m;
    let den = (y * 2u32) % &m;
    let lambda = (num * mod_inv(&den, &m)) % &m;
    let sq = (&lambda * &lambda) % &m;
    let x3 = mod_sub(&mod_sub(&sq, x, &m), x, &m);
    let y3 = mod_sub(&((lambda * mod_sub(x, &x3, &m)) % &m), y, &m);
    Some((x3, y3))
}

fn ec_mul(k: &BigUint, p: &(BigUint, BigUint)) -> EcPoint {
    let mut result: EcPoint = None;
    let mut cur: EcPoint = Some(p.clone());
    for byte in k.to_bytes_be() {
        for i in (0..8).rev() {
            if (byte >> i) & 1 == 1 {
                result = ec_add(&result, &cur);
            }
            cur = match &cur {
                Some((x, y)) => ec_double(x, y),
                None => None,
            };
        }
    }
    result
}

fn big_to_28(b: &BigUint) -> Vec<u8> {
    let bytes = b.to_bytes_be();
    let mut out = vec![0u8; 28];
    if bytes.len() > 28 {
        out.copy_from_slice(&bytes[bytes.len() - 28..]);
    } else {
        out[28 - bytes.len()..].copy_from_slice(&bytes);
    }
    out
}

/// ec115 EcdhCipher（对齐 pkg/crypto/ec115）
struct EcdhCipher {
    iv: Vec<u8>,
    pub_key: Vec<u8>,
    aes: Aes128,
}

impl EcdhCipher {
    fn new() -> Result<EcdhCipher, String> {
        let mut rng = rand::thread_rng();
        let n = p224_n();
        // 私钥 d ∈ [1, n-1]
        let mut bytes = [0u8; 28];
        rng.fill(&mut bytes);
        let d = BigUint::from_bytes_be(&bytes) % (&n - BigUint::from(1u32)) + BigUint::from(1u32);
        let remote = (
            BigUint::from_bytes_be(&EC115_REMOTE_PUB[..28]),
            BigUint::from_bytes_be(&EC115_REMOTE_PUB[28..]),
        );
        let (_qx, qy) = ec_mul(&d, &p224_g()).ok_or("115 ec115: 私钥乘基点得到无穷远点")?;
        let (sx, _sy) = ec_mul(&d, &remote).ok_or("115 ec115: ECDH 共享秘密为无穷远点")?;
        let secret = big_to_28(&sx);
        let mut buf = Vec::with_capacity(30);
        buf.push(29); // p224BaseLen + 1
                      // 压缩标志位：Y 奇偶（对齐 Go：奇 -> 0x03，偶 -> 0x02）
        let y_bytes = big_to_28(&qy);
        buf.push(if y_bytes[27] & 1 == 1 { 0x03 } else { 0x02 });
        buf.extend_from_slice(&y_bytes);
        Ok(EcdhCipher {
            iv: secret[12..28].to_vec(),
            pub_key: buf,
            aes: Aes128::new(secret[..16].try_into().unwrap()),
        })
    }

    /// AES-128-CBC + PKCS7 加密（对齐 Encrypt：链式块加密等价 CBC）
    fn encrypt(&self, plain: &[u8]) -> Vec<u8> {
        // PKCS7
        let pad = 16 - plain.len() % 16;
        let mut data = plain.to_vec();
        data.extend(std::iter::repeat_n(pad as u8, pad));
        let mut out = Vec::with_capacity(data.len());
        let mut prev = self.iv.clone();
        for block in data.chunks(16) {
            let mut tmp = [0u8; 16];
            for i in 0..16 {
                tmp[i] = block[i] ^ prev[i];
            }
            self.aes.encrypt_block(&mut tmp);
            out.extend_from_slice(&tmp);
            prev = tmp.to_vec();
        }
        out
    }

    /// AES-128-CBC 解密 + 2 字节长度头 + LZ4 解压（对齐 Decrypt）
    fn decrypt(&self, cipher: &[u8]) -> Result<Vec<u8>, String> {
        let n = cipher.len() - cipher.len() % 16;
        let cipher = &cipher[..n];
        let mut out = Vec::with_capacity(cipher.len());
        let mut prev = self.iv.clone();
        for block in cipher.chunks(16) {
            let mut tmp = [0u8; 16];
            tmp.copy_from_slice(block);
            self.aes.decrypt_block(&mut tmp);
            for i in 0..16 {
                tmp[i] ^= prev[i];
            }
            out.extend_from_slice(&tmp);
            prev = block.to_vec();
        }
        if out.len() < 2 {
            return Err("115 ec115: 解密数据过短".into());
        }
        let length = out[0] as usize + ((out[1] as usize) << 8);
        if 2 + length > out.len() {
            return Err("115 ec115: lz4 长度越界".into());
        }
        lz4_decompress(&out[2..2 + length])
    }

    /// 对齐 EncodeToken(timestamp)：pubKey 混淆 + crc 校验 + base64
    fn encode_token(&self, ts_millis: i64) -> String {
        let mut rng = rand::thread_rng();
        let r1: u8 = rng.gen_range(0..=255);
        let r2: u8 = rng.gen_range(0..=255);
        let mut tmp: Vec<u8> = Vec::with_capacity(74);
        for i in 0..15 {
            tmp.push(self.pub_key[i] ^ r1);
        }
        tmp.push(r1);
        tmp.push(0x73 ^ r1);
        for _ in 0..3 {
            tmp.push(r1);
        }
        let time = (ts_millis as u32).to_be_bytes();
        for i in 0..4 {
            tmp.push(r1 ^ time[3 - i]);
        }
        for i in 15..self.pub_key.len() {
            tmp.push(self.pub_key[i] ^ r2);
        }
        tmp.push(r2);
        tmp.push(0x01 ^ r2);
        for _ in 0..3 {
            tmp.push(r2);
        }
        // crc32(crcSalt ++ tmp) 大端逆序
        let mut crc_input = EC115_CRC_SALT.as_bytes().to_vec();
        crc_input.extend_from_slice(&tmp);
        let crc = crc32_ieee(&crc_input).to_be_bytes();
        for i in 0..4 {
            tmp.push(crc[3 - i]);
        }
        base64::engine::general_purpose::STANDARD.encode(&tmp)
    }
}

// ---------- OSS 参数 / token ----------

struct OssParams {
    bucket: String,
    object: String,
    callback: String,
    callback_var: String,
}

struct OssToken {
    access_key_id: String,
    access_key_secret: String,
    security_token: String,
}

/// oss_request() 参数结构体（参数对齐 Go 版 ossRequest(method, token, bucket, object, query, headers, contentType, body)）
struct OssRequestArgs<'a> {
    method: Method,
    token: &'a OssToken,
    bucket: &'a str,
    object: &'a str,
    query_sorted: &'a str,
    extra_oss_headers: &'a [(&'a str, String)],
    content_type: Option<&'a str>,
    body: Vec<u8>,
}

/// upload_part() 参数结构体（参数对齐 Go 版 uploadPart 分片上传入参）
struct OssPartArgs<'a> {
    token: &'a OssToken,
    params: &'a OssParams,
    upload_id: &'a str,
    tmp: &'a std::path::Path,
    offset: u64,
    chunk_size: u64,
    part_number: u64,
}

/// 对齐 115driver GenerateSignature：upper(sha1(userkey ++ sha1(uid+fileid+target+0) ++ "000000"))
fn generate_signature(user_id: i64, userkey: &str, file_id: &str, target: &str) -> String {
    let inner = sha1_hex(format!("{user_id}{file_id}{target}0").as_bytes());
    let sig_str = format!("{userkey}{inner}000000");
    sha1_hex(sig_str.as_bytes()).to_uppercase()
}

/// 对齐 115driver GenerateToken（Go 实现中 preID 参数未参与计算）
fn generate_token(
    file_id: &str,
    file_size: &str,
    sign_key: &str,
    sign_val: &str,
    user_id: &str,
    ts: &str,
    app_ver: &str,
) -> String {
    let uid_md5 = md5_hex(user_id.as_bytes());
    md5_hex(
        format!(
            "{MD5_SALT}{file_id}{file_size}{sign_key}{sign_val}{user_id}{ts}{uid_md5}{app_ver}"
        )
        .as_bytes(),
    )
}

/// 解析 OSS XML 响应中的单个标签
fn extract_xml_tag(xml: &str, tag: &str) -> Result<String, String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml
        .find(&open)
        .ok_or_else(|| format!("115 OSS 响应缺少 <{tag}>: {}", truncate_for_log(xml)))?
        + open.len();
    let end = xml[start..]
        .find(&close)
        .ok_or_else(|| format!("115 OSS 响应缺少 </{tag}>"))?
        + start;
    Ok(xml[start..end].to_string())
}

fn truncate_for_log(s: &str) -> String {
    if s.len() <= 200 {
        s.to_string()
    } else {
        format!("{}...", &s[..200])
    }
}

/// OSS callback 响应检查（对齐 UploadResult.Err：state=false 报错）
fn check_oss_callback_response(status: u16, body: &[u8]) -> Result<(), String> {
    if !(200..300).contains(&status) {
        return Err(format!(
            "115 OSS 上传失败：HTTP {status} {}",
            truncate_for_log(&String::from_utf8_lossy(body))
        ));
    }
    if body.is_empty() {
        return Ok(());
    }
    let v: Value =
        serde_json::from_slice(body).map_err(|e| format!("115 OSS callback 响应解析失败: {e}"))?;
    if v.get("state") == Some(&Value::Bool(false)) {
        let errno = coerce_str(v.get("errno"));
        let msg = v
            .get("error")
            .or_else(|| v.get("message"))
            .and_then(|x| x.as_str())
            .unwrap_or("");
        return Err(format!("115 OSS callback 失败(errno={errno}): {msg}"));
    }
    Ok(())
}

/// 对齐 Go SplitFile：返回 (offset, size) 分片列表
fn split_file(file_size: u64) -> Result<Vec<(u64, u64)>, String> {
    let mut chunks: Vec<(u64, u64)> = Vec::new();
    let mut split_done = false;
    for i in 1..10u64 {
        if file_size < i * GB {
            chunks = split_by_part_num(file_size, (i * 1000) as usize)?;
            split_done = true;
            break;
        }
    }
    if !split_done {
        // >= 9GB 分 10000 片
        chunks = split_by_part_num(file_size, 10000)?;
    }
    // 单个分片大小不能小于 100KB
    if !chunks.is_empty() && chunks[0].1 < 100 * KB {
        chunks = split_by_part_size(file_size, 100 * KB)?;
    }
    Ok(chunks)
}

/// 对齐 SplitFileByPartNum
fn split_by_part_num(file_size: u64, chunk_num: usize) -> Result<Vec<(u64, u64)>, String> {
    if chunk_num == 0 || chunk_num > 10000 {
        return Err("115 分片数非法".into());
    }
    let n = chunk_num as u64;
    if n > file_size {
        return Err("115 分片数大于文件大小".into());
    }
    let base = file_size / n;
    let mut chunks = Vec::with_capacity(chunk_num);
    for i in 0..n {
        let size = if i == n - 1 {
            file_size - base * (n - 1)
        } else {
            base
        };
        chunks.push((i * base, size));
    }
    Ok(chunks)
}

/// 对齐 SplitFileByPartSize
fn split_by_part_size(file_size: u64, chunk_size: u64) -> Result<Vec<(u64, u64)>, String> {
    if chunk_size == 0 {
        return Err("115 分片大小非法".into());
    }
    let n = file_size / chunk_size;
    if n >= 10000 {
        return Err("115 分片数过多，请增大分片大小".into());
    }
    let mut chunks = Vec::new();
    for i in 0..n {
        chunks.push((i * chunk_size, chunk_size));
    }
    if !file_size.is_multiple_of(chunk_size) {
        chunks.push((n * chunk_size, file_size % chunk_size));
    }
    Ok(chunks)
}

impl Pan115 {
    /// 当前 appVer（initAppVer 拉取后拼进 UA，此处从 UA 还原）
    fn app_ver(&self) -> String {
        let ua = self.ua();
        ua.strip_prefix("Mozilla/5.0 115Browser/")
            .filter(|s| !s.is_empty())
            .unwrap_or(FALLBACK_APP_VER)
            .to_string()
    }

    /// 对齐 UploadAvailable -> GetUploadInfo：拉取/缓存上传元信息
    async fn ensure_upload_meta(&self) -> Result<UploadMeta, String> {
        if let Some(m) = self.upload_meta.lock().unwrap().clone() {
            return Ok(m);
        }
        let v = self
            .request(Method::POST, API_UPLOAD_INFO, None, None)
            .await?;
        let user_id = v.get("user_id").and_then(|x| x.as_i64()).unwrap_or(0);
        let userkey = v
            .get("userkey")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let size_limit = coerce_str(v.get("size_limit")).parse::<i64>().unwrap_or(0);
        let allowed = v
            .get("upload_allowed")
            .and_then(|x| x.as_bool())
            .unwrap_or(false);
        if user_id == 0 || userkey.is_empty() {
            return Err("115 获取上传信息失败：user_id/userkey 为空".into());
        }
        if !allowed {
            return Err("115 上传不可用（upload_allowed=false，可能触发风控）".into());
        }
        let meta = UploadMeta {
            user_id,
            userkey,
            size_limit,
        };
        *self.upload_meta.lock().unwrap() = Some(meta.clone());
        Ok(meta)
    }

    /// 对齐 GetOSSToken：GET uplb.115.com/3.0/gettoken.php
    async fn get_oss_token(&self) -> Result<OssToken, String> {
        let v = self
            .request(Method::GET, API_UPLOAD_OSS_TOKEN, None, None)
            .await?;
        let status = v.get("StatusCode").and_then(|x| x.as_str()).unwrap_or("");
        if status != "200" {
            return Err(format!("115 获取 OSS token 失败：StatusCode={status}"));
        }
        Ok(OssToken {
            access_key_id: v
                .get("AccessKeyID")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            access_key_secret: v
                .get("AccessKeySecret")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            security_token: v
                .get("SecurityToken")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
        })
    }

    /// OSS V1 签名请求（对齐 aliyun-oss-go-sdk 默认签名 + OssOption）
    ///
    /// - 签名串：VERB\nContent-MD5\nContent-Type\nDate\nCanonicalizedOSSHeaders + CanonicalizedResource
    /// - query_sorted：已按 key 排序、参与签名的子资源 query（如 "sequential&uploads&x-oss-enable-sha1"）
    /// - extra_oss_headers：额外 x-oss-* 头（x-oss-callback / x-oss-callback-var）
    /// - 返回 (HTTP 状态码, ETag, 响应体)
    async fn oss_request(
        &self,
        args: OssRequestArgs<'_>,
    ) -> Result<(u16, Option<String>, Vec<u8>), String> {
        let OssRequestArgs {
            method,
            token,
            bucket,
            object,
            query_sorted,
            extra_oss_headers,
            content_type,
            body,
        } = args;
        let method_str = method.as_str().to_string();
        let date = gmt_http_date();
        // x-oss-* 头小写排序后进签名（对齐 getSignedStr）
        let mut oss_headers: Vec<(String, String)> =
            vec![("x-oss-security-token".into(), token.security_token.clone())];
        for (k, v) in extra_oss_headers {
            oss_headers.push((k.to_string(), v.clone()));
        }
        oss_headers.sort();
        let mut canonical_oss_headers = String::new();
        for (k, v) in &oss_headers {
            canonical_oss_headers.push_str(&format!("{k}:{v}\n"));
        }
        let resource = if query_sorted.is_empty() {
            format!("/{bucket}/{object}")
        } else {
            format!("/{bucket}/{object}?{query_sorted}")
        };
        let ct = content_type.unwrap_or("");
        let string_to_sign = format!(
            "{}\n{}\n{}\n{}\n{}{}",
            method_str, "", ct, date, canonical_oss_headers, resource
        );
        let sig = base64::engine::general_purpose::STANDARD.encode(hmac_sha1(
            token.access_key_secret.as_bytes(),
            string_to_sign.as_bytes(),
        ));

        let host = format!("{bucket}.{OSS_ENDPOINT}");
        let url = if query_sorted.is_empty() {
            format!("https://{host}/{}", escape_url_path(object))
        } else {
            format!(
                "https://{host}/{}?{}",
                escape_url_path(object),
                query_sorted
            )
        };
        let mut req = self
            .http
            .request(method, &url)
            .header("Date", date)
            .header("User-Agent", OSS_UA)
            .header(
                "Authorization",
                format!("OSS {}:{}", token.access_key_id, sig),
            )
            .header("x-oss-security-token", &token.security_token);
        if !ct.is_empty() {
            req = req.header("Content-Type", ct);
        }
        for (k, v) in extra_oss_headers {
            req = req.header(*k, v);
        }
        let resp = req
            .body(body)
            .send()
            .await
            .map_err(|e| format!("115 OSS 上传请求失败: {e}"))?;
        let status = resp.status().as_u16();
        let etag = resp
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| format!("115 OSS 响应读取失败: {e}"))?;
        Ok((status, etag, bytes.to_vec()))
    }

    /// 对齐 rapidUpload：ECDH 加密 form 请求 initupload.php（闪传预检/双向校验）
    async fn rapid_upload(
        &self,
        file_size: u64,
        file_name: &str,
        dir_id: &str,
        pre_id: &str,
        file_id: &str,
        tmp: &std::path::Path,
    ) -> Result<Value, String> {
        let _ = pre_id; // Go 版 GenerateToken 的 preID 参数未参与计算
        let meta = self.ensure_upload_meta().await?;
        let target = format!("U_1_{dir_id}");
        let sig = generate_signature(meta.user_id, &meta.userkey, file_id, &target);
        let app_ver = self.app_ver();
        let file_size_str = file_size.to_string();
        let user_id_str = meta.user_id.to_string();
        let cipher = EcdhCipher::new()?;

        let mut sign_key = String::new();
        let mut sign_val = String::new();
        loop {
            let t = unix_millis();
            let token = generate_token(
                file_id,
                &file_size_str,
                &sign_key,
                &sign_val,
                &user_id_str,
                &t.to_string(),
                &app_ver,
            );
            // 对齐 Go url.Values.Encode()：按 key 字典序拼接
            let mut fields: Vec<(String, String)> = vec![
                ("appid".into(), "0".into()),
                ("appversion".into(), app_ver.clone()),
                ("fileid".into(), file_id.to_string()),
                ("filename".into(), file_name.to_string()),
                ("filesize".into(), file_size_str.clone()),
                ("sig".into(), sig.clone()),
                ("t".into(), t.to_string()),
                ("target".into(), target.clone()),
                ("token".into(), token),
                ("userid".into(), user_id_str.clone()),
            ];
            if !sign_key.is_empty() {
                fields.push(("sign_key".into(), sign_key.clone()));
                fields.push(("sign_val".into(), sign_val.clone()));
            }
            fields.sort_by(|a, b| a.0.cmp(&b.0));
            let form_str = fields
                .iter()
                .map(|(k, v)| format!("{}={}", go_query_escape(k), go_query_escape(v)))
                .collect::<Vec<_>>()
                .join("&");

            let url = format!("{API_UPLOAD_INIT}?k_ec={}", cipher.encode_token(t as i64));
            let resp = self
                .http
                .request(Method::POST, &url)
                .header("Cookie", self.cookie())
                .header("User-Agent", self.ua())
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(cipher.encrypt(form_str.as_bytes()))
                .send()
                .await
                .map_err(|e| format!("115 上传预检请求失败: {e}"))?;
            let http_status = resp.status();
            let body_bytes = resp
                .bytes()
                .await
                .map_err(|e| format!("115 上传预检响应读取失败: {e}"))?;
            if http_status.as_u16() >= 400 {
                return Err(format!("115 上传预检 HTTP {http_status}"));
            }
            let decrypted = cipher.decrypt(&body_bytes)?;
            let v: Value = serde_json::from_slice(&decrypted)
                .map_err(|e| format!("115 上传预检响应解析失败: {e}"))?;
            // 对齐 UploadInitResp.Err：statuscode 为 0/701 视为成功
            let err_code = v.get("statuscode").and_then(|x| x.as_i64()).unwrap_or(0);
            if err_code != 0 && err_code != 701 {
                let msg = v.get("statusmsg").and_then(|x| x.as_str()).unwrap_or("");
                return Err(format!("115 上传预检失败(code={err_code}): {msg}"));
            }
            let status = v.get("status").and_then(|x| x.as_i64()).unwrap_or(0);
            if status == 7 {
                // 服务端要求二次校验：sign_check = "start-end"
                sign_key = v
                    .get("sign_key")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                let sign_check = v.get("sign_check").and_then(|x| x.as_str()).unwrap_or("");
                let Some((s, e)) = sign_check.split_once('-') else {
                    return Err(format!("115 上传预检 sign_check 格式非法: {sign_check}"));
                };
                let start: u64 = s
                    .trim()
                    .parse()
                    .map_err(|_| "115 sign_check 起始位置解析失败".to_string())?;
                let end: u64 = e
                    .trim()
                    .parse()
                    .map_err(|_| "115 sign_check 结束位置解析失败".to_string())?;
                sign_val = sha1_range_upper(tmp, start, end).await?;
                continue;
            }
            return Ok(v);
        }
    }

    /// 对齐 UploadByOSS：单请求直传（<=10MB）
    async fn upload_by_oss(
        &self,
        params: &OssParams,
        tmp: &std::path::Path,
        _size: u64,
    ) -> Result<(), String> {
        let token = self.get_oss_token().await?;
        let data = tokio::fs::read(tmp)
            .await
            .map_err(|e| format!("115 读取临时文件失败: {e}"))?;
        let callback = base64::engine::general_purpose::STANDARD.encode(params.callback.as_bytes());
        let callback_var =
            base64::engine::general_purpose::STANDARD.encode(params.callback_var.as_bytes());
        let (status, _, body) = self
            .oss_request(OssRequestArgs {
                method: Method::PUT,
                token: &token,
                bucket: &params.bucket,
                object: &params.object,
                query_sorted: "",
                extra_oss_headers: &[
                    ("x-oss-callback", callback),
                    ("x-oss-callback-var", callback_var),
                ],
                content_type: Some("application/octet-stream"),
                body: data,
            })
            .await?;
        check_oss_callback_response(status, &body)
    }

    /// 对齐 UploadByMultipart：init?uploads -> 逐片 PUT（顺序、每片重试 3 次）-> complete
    async fn upload_by_multipart(
        &self,
        params: &OssParams,
        tmp: &std::path::Path,
        size: u64,
    ) -> Result<(), String> {
        let token = self.get_oss_token().await?;
        let callback = base64::engine::general_purpose::STANDARD.encode(params.callback.as_bytes());
        let callback_var =
            base64::engine::general_purpose::STANDARD.encode(params.callback_var.as_bytes());
        let cb_headers = [
            ("x-oss-callback", callback.clone()),
            ("x-oss-callback-var", callback_var.clone()),
        ];
        let chunks = split_file(size)?;
        // InitiateMultipartUpload：Sequential()+EnableSha1() -> ?sequential&uploads&x-oss-enable-sha1
        let (status, _, body) = self
            .oss_request(OssRequestArgs {
                method: Method::POST,
                token: &token,
                bucket: &params.bucket,
                object: &params.object,
                query_sorted: "sequential&uploads&x-oss-enable-sha1",
                extra_oss_headers: &cb_headers,
                content_type: Some("application/octet-stream"),
                body: Vec::new(),
            })
            .await?;
        if !(200..300).contains(&status) {
            return Err(format!(
                "115 OSS 初始化分片上传失败：HTTP {status} {}",
                truncate_for_log(&String::from_utf8_lossy(&body))
            ));
        }
        let upload_id = extract_xml_tag(&String::from_utf8_lossy(&body), "UploadId")?;

        // 逐片顺序上传（oss Sequential 模式必须按序；每片最多重试 3 次）
        let mut parts: Vec<(u64, String)> = Vec::with_capacity(chunks.len());
        for (idx, (offset, chunk_size)) in chunks.iter().enumerate() {
            let part_number = (idx + 1) as u64;
            let mut etag = String::new();
            let mut last_err = String::new();
            for _ in 0..3 {
                match self
                    .upload_part(OssPartArgs {
                        token: &token,
                        params,
                        upload_id: &upload_id,
                        tmp,
                        offset: *offset,
                        chunk_size: *chunk_size,
                        part_number,
                    })
                    .await
                {
                    Ok(e) => {
                        etag = e;
                        last_err.clear();
                        break;
                    }
                    Err(e) => last_err = e,
                }
            }
            if !last_err.is_empty() {
                return Err(format!("115 OSS 分片 {part_number} 上传失败: {last_err}"));
            }
            parts.push((part_number, etag));
        }

        // CompleteMultipartUpload
        let mut xml = String::from("<CompleteMultipartUpload>");
        for (num, etag) in &parts {
            xml.push_str(&format!(
                "<Part><PartNumber>{num}</PartNumber><ETag>{etag}</ETag></Part>"
            ));
        }
        xml.push_str("</CompleteMultipartUpload>");
        let (status, _, body) = self
            .oss_request(OssRequestArgs {
                method: Method::POST,
                token: &token,
                bucket: &params.bucket,
                object: &params.object,
                query_sorted: &format!("uploadId={}", go_query_escape(&upload_id)),
                extra_oss_headers: &cb_headers,
                content_type: None,
                body: xml.into_bytes(),
            })
            .await?;
        check_oss_callback_response(status, &body)
    }

    /// 单个分片上传，返回 ETag
    async fn upload_part(&self, args: OssPartArgs<'_>) -> Result<String, String> {
        let OssPartArgs {
            token,
            params,
            upload_id,
            tmp,
            offset,
            chunk_size,
            part_number,
        } = args;
        let mut f = tokio::fs::File::open(tmp)
            .await
            .map_err(|e| format!("115 打开临时文件失败: {e}"))?;
        f.seek(std::io::SeekFrom::Start(offset))
            .await
            .map_err(|e| format!("115 临时文件 seek 失败: {e}"))?;
        let mut data = vec![0u8; chunk_size as usize];
        f.read_exact(&mut data)
            .await
            .map_err(|e| format!("115 读取临时分片失败: {e}"))?;
        let query = format!(
            "partNumber={part_number}&uploadId={}",
            go_query_escape(upload_id)
        );
        let callback = base64::engine::general_purpose::STANDARD.encode(params.callback.as_bytes());
        let callback_var =
            base64::engine::general_purpose::STANDARD.encode(params.callback_var.as_bytes());
        let (status, etag, body) = self
            .oss_request(OssRequestArgs {
                method: Method::PUT,
                token,
                bucket: &params.bucket,
                object: &params.object,
                query_sorted: &query,
                extra_oss_headers: &[
                    ("x-oss-callback", callback),
                    ("x-oss-callback-var", callback_var),
                ],
                content_type: None,
                body: data,
            })
            .await?;
        if !(200..300).contains(&status) {
            return Err(format!(
                "HTTP {status} {}",
                truncate_for_log(&String::from_utf8_lossy(&body))
            ));
        }
        etag.ok_or_else(|| "115 OSS 分片响应缺少 ETag".into())
    }

    /// 对齐 Go 版 MakeDir
    pub async fn mkdir(&self, parent_fid: &str, name: &str) -> Result<(), String> {
        if parent_fid.is_empty() {
            return Err("115 新建文件夹失败：父目录 ID 为空".into());
        }
        let form = [("pid", parent_fid.to_string()), ("cname", name.to_string())];
        self.request(Method::POST, API_DIR_ADD, None, Some(&form))
            .await?;
        Ok(())
    }

    /// 对齐 Go 版 Rename（115driver Rename：fid + files_new_name[fid]）
    pub async fn rename(&self, parent_fid: &str, e: &Entry, new_name: &str) -> Result<(), String> {
        let _ = parent_fid;
        let key = format!("files_new_name[{}]", e.fid);
        let form = [
            ("fid", e.fid.clone()),
            ("file_name", new_name.to_string()),
            (key.as_str(), new_name.to_string()),
        ];
        self.request(Method::POST, API_FILE_RENAME, None, Some(&form))
            .await?;
        Ok(())
    }

    /// 对齐 Go 版 Move（115driver Move：pid + fid[0]）
    pub async fn move_entry(
        &self,
        parent_fid: &str,
        e: &Entry,
        dst_dir_fid: &str,
    ) -> Result<(), String> {
        let _ = parent_fid;
        let form = [("pid", dst_dir_fid.to_string()), ("fid[0]", e.fid.clone())];
        self.request(Method::POST, API_FILE_MOVE, None, Some(&form))
            .await?;
        Ok(())
    }

    /// 对齐 Go 版 Copy（115driver Copy：pid + fid[0]）
    pub async fn copy(&self, parent_fid: &str, e: &Entry, dst_dir_fid: &str) -> Result<(), String> {
        let _ = parent_fid;
        let form = [("pid", dst_dir_fid.to_string()), ("fid[0]", e.fid.clone())];
        self.request(Method::POST, API_FILE_COPY, None, Some(&form))
            .await?;
        Ok(())
    }

    /// 对齐 Go 版 Remove（115driver Delete：fid[0]）
    pub async fn remove(&self, parent_fid: &str, e: &Entry) -> Result<(), String> {
        let _ = parent_fid;
        let form = [("fid[0]", e.fid.clone())];
        self.request(Method::POST, API_FILE_DELETE, None, Some(&form))
            .await?;
        Ok(())
    }

    /// 对齐 Go 版 Put（115 上传全流程）：
    /// uploadinfo 预检 -> 落临时文件算 sha1（全量 + 前 128KB）->
    /// initupload.php（ECDH 加密，闪传/双向校验）-> OSS 直传（<=10MB 单请求，
    /// >10MB 分片；V1 签名 + callback 回调确认）
    pub async fn put(&self, dst_dir_fid: &str, input: super::PutInput) -> Result<(), String> {
        // 1. 上传预检（对齐 UploadAvailable）
        let meta = self.ensure_upload_meta().await?;
        // 2. reader 只能读一次：先落临时文件并计算 sha1
        let tmp = temp_file_path();
        let _guard = TempFileGuard(tmp.clone());
        let (actual_size, full_sha1, pre_sha1) = spool_and_sha1(input.reader, &tmp).await?;
        let size = if input.size != 0 {
            input.size
        } else {
            actual_size
        };
        if meta.size_limit > 0 && size > meta.size_limit as u64 {
            return Err(format!(
                "115 文件过大：{size} 字节超过上限 {} 字节",
                meta.size_limit
            ));
        }
        let file_id = full_sha1.to_uppercase();
        let pre_id = pre_sha1.to_uppercase();
        // 3. 闪传预检（对齐 rapidUpload）
        let init = self
            .rapid_upload(size, &input.name, dst_dir_fid, &pre_id, &file_id, &tmp)
            .await?;
        let status = init.get("status").and_then(|x| x.as_i64()).unwrap_or(0);
        if status == 2 {
            // 闪传命中，秒传完成
            return Ok(());
        }
        // 对齐 UploadInitResp.Ok()：status 仅 1（继续上传）/ 2（秒传）合法
        if status != 1 {
            return Err(format!("115 上传预检返回异常状态：{status}"));
        }
        let bucket = init
            .get("bucket")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let object = init
            .get("object")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if bucket.is_empty() || object.is_empty() {
            return Err("115 上传失败：预检响应缺少 OSS bucket/object".into());
        }
        let oss_params = OssParams {
            bucket,
            object,
            callback: init
                .pointer("/callback/callback")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            callback_var: init
                .pointer("/callback/callback_var")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
        };
        // 4. OSS 上传（对齐 Put 的 10MB 分界）
        if size <= 10 * MB {
            self.upload_by_oss(&oss_params, &tmp, size).await
        } else {
            self.upload_by_multipart(&oss_params, &tmp, size).await
        }
    }
}
