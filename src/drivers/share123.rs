//! 123 云盘分享驱动（对齐 Go 版 drivers/123_share，只读）
//!
//! - 授权：shareKey（分享链接里的 key）+ 可选分享密码，AccessToken 可选
//! - 列目录：GET /b/api/share/get（分页，Next == "-1" 结束）
//! - 下载：POST /b/api/share/download/info 取 DownloadURL，
//!   URL 带 params 参数时为 base64 真链，再跟随 302 拿最终直链
//! - 防爬：接口需 timeSign 签名（crc32 算法，对齐 signPath）

use super::DownloadInfo;
use crate::config::Entry;
use reqwest::{redirect, Client, ClientBuilder, Method};
use serde_json::{json, Value};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

const B_API: &str = "https://yun.123pan.com/b/api";
const FILE_LIST: &str = "/share/get";
const DOWNLOAD_INFO: &str = "/share/download/info";
const REFERER: &str = "https://yun.123pan.com/";
const UA: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) openlist-client";
const RATE_LIMIT: Duration = Duration::from_millis(700);

pub struct Pan123Share {
    share_key: String,
    share_pwd: String,
    access_token: String,
    http: Client,
    http_no_redirect: Client,
    last_req: Mutex<Option<Instant>>,
}

impl Pan123Share {
    pub fn new(share_key: String, share_pwd: String, access_token: String) -> Self {
        Pan123Share {
            share_key,
            share_pwd,
            access_token,
            http: Client::new(),
            http_no_redirect: ClientBuilder::new()
                .redirect(redirect::Policy::none())
                .build()
                .unwrap(),
            last_req: Mutex::new(None),
        }
    }

    /// 对齐 Init()：无登录逻辑，仅要求 shareKey 非空
    pub fn validate(&self) -> Result<(), String> {
        if self.share_key.is_empty() {
            return Err("123 分享 shareKey 不能为空".into());
        }
        Ok(())
    }

    /// 对齐 APIRateLimit：同接口 700ms 间隔
    async fn rate_limit(&self) {
        loop {
            let wait = {
                let mut last = self.last_req.lock().unwrap();
                match *last {
                    Some(t) if t.elapsed() < RATE_LIMIT => RATE_LIMIT - t.elapsed(),
                    _ => {
                        *last = Some(Instant::now());
                        return;
                    }
                }
            };
            tokio::time::sleep(wait).await;
        }
    }

    /// 对齐 request()：自动加 timeSign 签名，code != 0 报错
    async fn request(
        &self,
        path: &str,
        method: Method,
        query: &[(&str, String)],
        body: Option<Value>,
    ) -> Result<Value, String> {
        let url = format!("{B_API}{}", get_api_signed(path));
        let mut req = self
            .http
            .request(method, &url)
            .header("origin", "https://yun.123pan.com")
            .header("referer", REFERER)
            .header("authorization", format!("Bearer {}", self.access_token))
            .header("user-agent", UA)
            .header("platform", "web")
            .header("app-version", "3");
        for (k, v) in query {
            req = req.query(&[(k, v)]);
        }
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req.send().await.map_err(|e| format!("请求失败: {e}"))?;
        let v: Value = resp
            .json()
            .await
            .map_err(|e| format!("123 分享响应解析失败: {e}"))?;
        let code = v.get("code").and_then(|x| x.as_i64()).unwrap_or(-1);
        if code != 0 {
            let msg = v
                .get("message")
                .and_then(|x| x.as_str())
                .unwrap_or("unknown")
                .to_string();
            return Err(format!("123 分享接口错误(code={code}): {msg}"));
        }
        Ok(v)
    }

    /// 对齐 getFiles()：分页拉取
    pub async fn list(&self, parent_fid: &str) -> Result<Vec<Entry>, String> {
        let parent = if parent_fid.is_empty() {
            "0"
        } else {
            parent_fid
        };
        let mut page = 1i64;
        let mut out = Vec::new();
        loop {
            self.rate_limit().await;
            let resp = self
                .request(
                    FILE_LIST,
                    Method::GET,
                    &[
                        ("limit", "100".into()),
                        ("next", "0".into()),
                        ("orderBy", "file_id".into()),
                        ("orderDirection", "desc".into()),
                        ("parentFileId", parent.to_string()),
                        ("Page", page.to_string()),
                        ("shareKey", self.share_key.clone()),
                        ("SharePwd", self.share_pwd.clone()),
                    ],
                    None,
                )
                .await?;
            let info_list = resp
                .pointer("/data/InfoList")
                .and_then(|x| x.as_array())
                .cloned()
                .unwrap_or_default();
            let next = resp
                .pointer("/data/Next")
                .and_then(|x| x.as_str())
                .unwrap_or("-1")
                .to_string();
            for f in &info_list {
                out.push(file_to_entry(f));
            }
            if info_list.is_empty() || next == "-1" {
                break;
            }
            page += 1;
        }
        Ok(out)
    }

    /// 对齐 Link()：download/info -> base64 params -> 跟随 302
    pub async fn download(&self, e: &Entry) -> Result<DownloadInfo, String> {
        if e.is_dir {
            return Err("目录无法下载".into());
        }
        let file_id: i64 = e
            .fid
            .parse()
            .map_err(|_| format!("123 分享文件 ID 非法: {}", e.fid))?;
        let body = json!({
            "shareKey": self.share_key,
            "SharePwd": self.share_pwd,
            "etag": e.etag.clone().unwrap_or_default(),
            "fileId": file_id,
            "s3keyFlag": e.s3_key_flag.clone().unwrap_or_default(),
            "size": e.size,
        });
        let resp = self
            .request(DOWNLOAD_INFO, Method::POST, &[], Some(body))
            .await?;
        let download_url = resp
            .pointer("/data/DownloadURL")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if download_url.is_empty() {
            return Err("123 分享未取到下载地址".into());
        }

        // URL 带 params 参数时为 base64 编码的真链（对齐 Go 逻辑）
        let mut u_ = download_url.clone();
        if let Ok(ou) = url::Url::parse(&download_url) {
            if let Some(params) = ou
                .query_pairs()
                .find(|(k, _)| k == "params")
                .map(|(_, v)| v.to_string())
            {
                use base64::Engine;
                if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(&params) {
                    if let Ok(s) = String::from_utf8(decoded) {
                        if url::Url::parse(&s).is_ok() {
                            u_ = s;
                        }
                    }
                }
            }
        }

        // 请求一次（禁重定向）：302 -> location；否则 JSON 里的 redirect_url
        let mut location = String::new();
        let resp = self
            .http_no_redirect
            .get(&u_)
            .header("Referer", REFERER)
            .send()
            .await
            .map_err(|e| format!("获取直链失败: {e}"))?;
        let status = resp.status().as_u16();
        if status == 302 {
            location = resp
                .headers()
                .get("location")
                .and_then(|l| l.to_str().ok())
                .unwrap_or("")
                .to_string();
        } else if status < 300 {
            let body = resp
                .text()
                .await
                .map_err(|e| format!("读取响应失败: {e}"))?;
            if let Ok(v) = serde_json::from_str::<Value>(&body) {
                location = v
                    .pointer("/data/redirect_url")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
            }
        }
        if !location.is_empty() {
            u_ = location;
        }

        // Referer 取原始 DownloadURL 的 scheme://host/（对齐 Go）
        let referer = url::Url::parse(&download_url)
            .map(|u| format!("{}://{}/", u.scheme(), u.host_str().unwrap_or("")))
            .unwrap_or_else(|_| REFERER.to_string());

        Ok(DownloadInfo {
            url: u_,
            headers: vec![("Referer".into(), referer)],
            proxy: true,
            local_path: None,
        })
    }

    // ---------- 写操作 ----------
    // 对齐 Go 版 drivers/123_share：MakeDir/Move/Rename/Copy/Remove/Put
    // 全部为 errs.NotSupport 占位，此驱动只读，不做任何网络调用。

    /// 对齐 MakeDir()：errs.NotSupport
    pub async fn mkdir(&self, _parent_fid: &str, _name: &str) -> Result<(), String> {
        Err("123 分享为只读驱动，不支持此操作".into())
    }

    /// 对齐 Rename()：errs.NotSupport
    pub async fn rename(
        &self,
        _parent_fid: &str,
        _e: &Entry,
        _new_name: &str,
    ) -> Result<(), String> {
        Err("123 分享为只读驱动，不支持此操作".into())
    }

    /// 对齐 Move()：errs.NotSupport
    pub async fn move_entry(
        &self,
        _parent_fid: &str,
        _e: &Entry,
        _dst_dir_fid: &str,
    ) -> Result<(), String> {
        Err("123 分享为只读驱动，不支持此操作".into())
    }

    /// 对齐 Copy()：errs.NotSupport
    pub async fn copy(
        &self,
        _parent_fid: &str,
        _e: &Entry,
        _dst_dir_fid: &str,
    ) -> Result<(), String> {
        Err("123 分享为只读驱动，不支持此操作".into())
    }

    /// 对齐 Remove()：errs.NotSupport
    pub async fn remove(&self, _parent_fid: &str, _e: &Entry) -> Result<(), String> {
        Err("123 分享为只读驱动，不支持此操作".into())
    }

    /// 对齐 Put()：errs.NotSupport
    pub async fn put(&self, _dst_dir_fid: &str, _input: super::PutInput) -> Result<(), String> {
        Err("123 分享为只读驱动，不支持此操作".into())
    }
}

fn file_to_entry(f: &Value) -> Entry {
    let file_id = f.get("FileId").and_then(|x| x.as_i64()).unwrap_or(0);
    let ftype = f.get("Type").and_then(|x| x.as_i64()).unwrap_or(0);
    Entry {
        fid: file_id.to_string(),
        name: f
            .get("FileName")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
        size: f.get("Size").and_then(|x| x.as_u64()).unwrap_or(0),
        is_dir: ftype == 1,
        updated_at: f
            .get("UpdateAt")
            .and_then(|x| x.as_str())
            .and_then(parse_iso8601_cst_ms),
        etag: f
            .get("Etag")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string()),
        s3_key_flag: f
            .get("S3KeyFlag")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string()),
        file_type: Some(ftype),
        extra: None,
    }
}

/// 解析 "2024-01-01T12:34:56.123+08:00" 类时间戳为毫秒（处理时区偏移）
fn parse_iso8601_cst_ms(s: &str) -> Option<i64> {
    let (date, rest) = s.split_once('T')?;
    let d: Vec<&str> = date.split('-').collect();
    if d.len() < 3 {
        return None;
    }
    let y = d[0].parse::<i64>().ok()?;
    let mo = d[1].parse::<i64>().ok()?;
    let dd = d[2].parse::<i64>().ok()?;
    // 时区偏移：+HH:MM / -HH:MM / Z
    let mut offset_secs: i64 = 0;
    let time_part = if let Some(idx) = rest.find('+') {
        offset_secs = parse_hhmm(&rest[idx + 1..]);
        &rest[..idx]
    } else if let Some(idx) = rest.find('-') {
        offset_secs = -parse_hhmm(&rest[idx + 1..]);
        &rest[..idx]
    } else {
        rest.strip_suffix('Z').unwrap_or(rest)
    };
    let t: Vec<&str> = time_part.split(':').collect();
    if t.len() < 3 {
        return None;
    }
    let h = t[0].parse::<i64>().ok()?;
    let mi = t[1].parse::<i64>().ok()?;
    let sec = t[2].split('.').next().unwrap_or(t[2]).parse::<i64>().ok()?;
    let days = days_from_civil(y, mo, dd);
    Some(((days * 86_400 + h * 3600 + mi * 60 + sec) - offset_secs) * 1000)
}

fn parse_hhmm(s: &str) -> i64 {
    let t: Vec<&str> = s.split(':').collect();
    match (t.first(), t.get(1)) {
        (Some(h), Some(m)) => {
            h.trim().parse::<i64>().unwrap_or(0) * 3600 + m.trim().parse::<i64>().unwrap_or(0) * 60
        }
        (Some(h), None) => h.trim().parse::<i64>().unwrap_or(0) * 3600,
        _ => 0,
    }
}

// 日期换算统一走 drivers/timeutil（原为本地副本）
use super::timeutil::{civil_from_days, days_from_civil};

// ---------- CRC32（IEEE，对齐 Go hash/crc32 ChecksumIEEE） ----------

fn crc32_table() -> &'static [u32; 256] {
    static TABLE: OnceLock<[u32; 256]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, item) in t.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    0xEDB8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
            }
            *item = c;
        }
        t
    })
}

pub(crate) fn crc32_ieee(data: &[u8]) -> u32 {
    let table = crc32_table();
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc = (crc >> 8) ^ table[((crc ^ b as u32) & 0xFF) as usize];
    }
    !crc
}

// ---------- timeSign 签名（对齐 Go signPath） ----------

/// 对齐 signPath(path, os="web", version="3")：返回签名值
/// 作为单个 query 参数 timeSign=<k> 挂到 URL 上（k 由本函数直接返回完整值）
fn sign_path(path: &str, os: &str, version: &str) -> String {
    const TABLE: &[u8; 26] = b"adefghlmyijnopkqrstubcvwsz";
    use rand::Rng;
    let random: i64 = (1e7 * rand::thread_rng().gen::<f64>()).round() as i64;
    // 东八区当前时间：unix 秒 + 8h
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        + 8 * 3600;
    let timestamp = now.to_string();
    // "200601021504"：yyyymmddHHMM
    let days = now.div_euclid(86_400);
    let rem = now.rem_euclid(86_400);
    let (y, mo, dd) = civil_from_days(days);
    let now_str = format!(
        "{y:04}{mo:02}{dd:02}{:02}{:02}",
        rem / 3600,
        (rem % 3600) / 60
    );
    let mapped: Vec<u8> = now_str
        .bytes()
        .map(|b| TABLE[(b - b'0') as usize])
        .collect();
    let time_sign = crc32_ieee(&mapped);
    let random_str = random.to_string();
    let time_sign_str = time_sign.to_string();
    let data = [
        timestamp.as_str(),
        random_str.as_str(),
        path,
        os,
        version,
        time_sign_str.as_str(),
    ]
    .join("|");
    let data_sign = crc32_ieee(data.as_bytes());
    format!("{timestamp}-{random}-{data_sign}")
}

/// 对齐 GetApi()：在路径 query 上追加签名参数
fn get_api_signed(path: &str) -> String {
    let sign = sign_path(path, "web", "3");
    match path.contains('?') {
        true => format!("{path}&timeSign={sign}"),
        false => format!("{path}?timeSign={sign}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32() {
        // 与 Go hash/crc32.ChecksumIEEE 对齐的标准值
        assert_eq!(crc32_ieee(b"123456789"), 0xCBF43926);
        assert_eq!(crc32_ieee(b""), 0);
    }

    #[test]
    fn test_sign_path_format() {
        let s = sign_path("/share/get", "web", "3");
        let parts: Vec<&str> = s.split('-').collect();
        assert_eq!(parts.len(), 3, "签名应为 timestamp-random-dataSign: {s}");
        assert!(parts[0].parse::<i64>().is_ok());
        assert!(parts[1].parse::<i64>().is_ok());
        assert!(parts[2].parse::<u32>().is_ok());
    }

    #[test]
    fn test_parse_iso() {
        assert_eq!(
            parse_iso8601_cst_ms("2024-01-01T08:00:00+08:00"),
            Some(1_704_067_200_000)
        );
    }

    #[test]
    fn test_get_api_signed() {
        let s = get_api_signed("/share/get");
        assert!(s.starts_with("/share/get?timeSign="));
    }
}
