//! 蓝奏云驱动（对齐 Go 版 drivers/lanzou，account / cookie 双模式）
//!
//! - 授权：account 模式用账号密码登录 up.woozooo.com 自动换 cookie（过期自动重登）；
//!   cookie 模式直接填 pc.woozooo.com 登录后的 cookie
//! - 列目录：POST /doupload.php（task=47 文件夹 / task=5 文件分页）
//! - 下载：task=22 取文件分享信息 -> 请求分享页 -> 解析下载页参数 ->
//!   POST ajax 拿中转地址 -> 跟随 302（或二次验证 el=2）拿真实直链
//!
//! 防爬：页面可能返回 JS 加密的 acw_sc__v2 验证页，需按算法计算 cookie 重试。

use super::DownloadInfo;
use crate::config::Entry;
use regex::Regex;
use reqwest::{redirect, Client, ClientBuilder, Method};
use serde_json::Value;
use std::sync::Mutex;

const BASE_URL: &str = "https://pc.woozooo.com";
const LOGIN_URL: &str = "https://up.woozooo.com/mlogin.php";
const SHARE_URL: &str = "https://pan.lanzoui.com";
const DEFAULT_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.39 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.39";

pub struct Lanzou {
    http: Client,
    http_no_redirect: Client,
    cookie: Mutex<String>,
    uid: Mutex<String>,
    vei: Mutex<String>,
    /// 账号密码非空时为 account 模式（cookie 过期自动重登）
    account: String,
    password: String,
}

// ---------- acw_sc__v2 ----------

/// 对齐 CalcAcwScV2：arg1 按固定 box 重排后与 mask 异或
fn calc_acw_sc_v2(html: &str) -> Result<String, String> {
    let re = Regex::new(r"arg1='([0-9A-Z]+)'").unwrap();
    let arg1 = re
        .captures(html)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
        .ok_or("无法匹配到 acw_sc__v2 arg1 参数")?;
    let mask = "3000176000856006061501533003690027800375";
    let unboxed = unbox(&arg1);
    hex_xor(&unboxed, mask).map_err(|e| format!("acw_sc__v2 hexXor 失败: {e}"))
}

fn unbox(hex_str: &str) -> String {
    let b = [
        6usize, 28, 34, 31, 33, 18, 30, 23, 9, 8, 19, 38, 17, 24, 0, 5, 32, 21, 10, 22, 25, 14, 15,
        3, 16, 27, 13, 35, 2, 29, 11, 26, 4, 36, 1, 39, 37, 7, 20, 12,
    ];
    let bytes = hex_str.as_bytes();
    let mut out = vec![b'0'; hex_str.len()];
    for (i, &j) in b.iter().enumerate() {
        if j < out.len() && i < bytes.len() {
            out[j] = bytes[i];
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

fn hex_xor(hex1: &str, hex2: &str) -> Result<String, String> {
    let b1 = hex_decode(hex1)?;
    let b2 = hex_decode(hex2)?;
    let n = b1.len().min(b2.len());
    let out: Vec<u8> = (0..n).map(|i| b1[i] ^ b2[i]).collect();
    Ok(out.iter().map(|b| format!("{b:02x}")).collect())
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

// ---------- HTML / JS 解析工具（对齐 help.go） ----------

/// 对齐 RemoveNotes
fn remove_notes(html: &str) -> String {
    let re = Regex::new(r"<!--.*?-->|[^:]//.*|/\*.*?\*/").unwrap();
    re.replace_all(html, |caps: &regex::Captures| {
        let b = caps.get(0).map(|m| m.as_str()).unwrap_or("");
        if b.len() >= 3 && &b[1..3] == "//" {
            b[..1].to_string()
        } else {
            "\n".to_string()
        }
    })
    .to_string()
}

/// 对齐 RemoveJSComment：状态机去除 JS 注释
fn remove_js_comment(data: &str) -> String {
    let bytes = data.as_bytes();
    let mut result = String::with_capacity(data.len());
    let (mut in_comment, mut in_line) = (false, false);
    let mut i = 0;
    while i < bytes.len() {
        let v = bytes[i];
        if in_line && (v == b'\n' || v == b'\r') {
            in_line = false;
            result.push(v as char);
            i += 1;
            continue;
        }
        if in_comment && v == b'*' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            in_comment = false;
            i += 2;
            continue;
        }
        if in_comment || in_line {
            i += 1;
            continue;
        }
        if v == b'/' && i + 1 < bytes.len() {
            match bytes[i + 1] {
                b'*' => {
                    in_comment = true;
                    i += 2;
                    continue;
                }
                b'/' => {
                    in_line = true;
                    i += 2;
                    continue;
                }
                _ => {}
            }
        }
        // 非ASCII字节按字节透传（UTF-8 多字节安全：这些字节不会匹配上面的 ASCII）
        let ch_len = utf8_len(v);
        result.push_str(&data[i..i + ch_len]);
        i += ch_len;
    }
    result
}

fn utf8_len(b: u8) -> usize {
    if b < 0x80 {
        1
    } else if b >> 5 == 0b110 {
        2
    } else if b >> 4 == 0b1110 {
        3
    } else if b >> 3 == 0b11110 {
        4
    } else {
        1
    }
}

/// 对齐 htmlJsonToMap：解析 html 里 data: {...} JSON（含 JS 变量回查）
fn html_json_to_map(html: &str) -> Result<Vec<(String, String)>, String> {
    let data_re = Regex::new(r"data[:\s]+(\{[^}]+\})").unwrap();
    let caps = data_re.captures(html).ok_or("html 中未找到 data JSON")?;
    let data = caps.get(1).map(|m| m.as_str()).unwrap_or("");
    Ok(json_to_map(data, html))
}

fn json_to_map(data: &str, html: &str) -> Vec<(String, String)> {
    let kv_re = Regex::new(r"'(.+?)':('?([^' },]*)'?)").unwrap();
    let mut out = Vec::new();
    for kv in kv_re.captures_iter(data) {
        let k = kv.get(1).map(|m| m.as_str()).unwrap_or("");
        let raw = kv.get(2).map(|m| m.as_str()).unwrap_or("");
        let v = kv.get(3).map(|m| m.as_str()).unwrap_or("");
        let val = if v.is_empty() || raw.contains('\'') || v.bytes().all(|b| b.is_ascii_digit()) {
            v.to_string()
        } else {
            find_js_var_func(v, html)
        };
        out.push((k.to_string(), val));
    }
    out
}

/// 对齐 findJSVarFunc：查 var <key> = ...;（取最后一个非空）
fn find_js_var_func(key: &str, data: &str) -> String {
    let re = Regex::new(&format!(
        r#"var\s+{}\s*=\s*['"]?([^'"]*)['"]?\s*;"#,
        regex::escape(key)
    ))
    .unwrap();
    let mut last = String::new();
    for cap in re.captures_iter(data) {
        let v = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        if !v.is_empty() {
            return v.to_string();
        }
        last = v.to_string();
    }
    last
}

/// 对齐 getJSFunctionByName：按名取 JS 函数源码
fn get_js_function_by_name(html: &str, name: &str) -> Result<String, String> {
    let re = Regex::new(r"(?is)function[^{]+").unwrap();
    for m in re.find_iter(html) {
        let start = m.start();
        // 从函数签名后配对大括号
        let rest = &html[m.end()..];
        let mut count = 0i32;
        for (ii, &v) in rest.as_bytes().iter().enumerate() {
            if v == b' ' && count == 0 {
                continue;
            }
            match v {
                b'{' => count += 1,
                b'}' => count -= 1,
                _ => {}
            }
            if count == 0 {
                let func = &html[start..m.end() + ii + 1];
                let name_re = Regex::new(&format!(r"function\s+{name}[()\s]+\{{")).unwrap();
                if name_re.is_match(func) {
                    return Ok(func.to_string());
                }
                break;
            }
        }
    }
    Err(format!("未找到 {name} 函数"))
}

// ---------- 大小 / 时间解析 ----------

fn size_str_to_u64(s: &str) -> u64 {
    let re = Regex::new(r"(?i)([0-9.]+)\s*([bkm]+)").unwrap();
    let Some(c) = re.captures(s) else {
        return 0;
    };
    let v: f64 = c
        .get(1)
        .and_then(|m| m.as_str().parse().ok())
        .unwrap_or(0.0);
    let unit = c
        .get(2)
        .map(|m| m.as_str().to_uppercase())
        .unwrap_or_default();
    match unit.as_str() {
        "B" => v as u64,
        "K" => (v * 1024.0) as u64,
        "M" => (v * 1024.0 * 1024.0) as u64,
        _ => 0,
    }
}

/// 对齐 MustParseTime：支持 "YYYY-MM-DD" 与相对时间（x秒/分钟/小时/天前、昨天/前天）
fn parse_time_to_ms(s: &str) -> Option<i64> {
    let date_re = Regex::new(r"\d{4}-\d{2}-\d{2}").unwrap();
    if let Some(d) = date_re.find(s) {
        let ds = d.as_str();
        let num = |r: std::ops::Range<usize>| ds.get(r).and_then(|x| x.parse::<i64>().ok());
        let (y, mo, dd) = (num(0..4)?, num(5..7)?, num(8..10)?);
        let y2 = if mo <= 2 { y - 1 } else { y };
        let era = y2.div_euclid(400);
        let yoe = y2 - era * 400;
        let mp = (mo + 9) % 12;
        let doy = (153 * mp + 2) / 5 + dd - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        return Some((era * 146_097 + doe - 719_468) * 86_400_000);
    }
    // 相对时间
    let re = Regex::new(r"([0-9.]*)\s*([\u{4e00}-\u{9fa5}]+)").unwrap();
    let c = re.captures(s)?;
    let n: i64 = c.get(1).and_then(|m| m.as_str().parse().ok()).unwrap_or(1);
    let unit = c.get(2).map(|m| m.as_str()).unwrap_or("");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let delta: i64 = match unit {
        "秒前" => n * 1000,
        "分钟前" => n * 60 * 1000,
        "小时前" => n * 3600 * 1000,
        "天前" => n * 86_400_000,
        "昨天" => 86_400_000,
        "前天" => 2 * 86_400_000,
        _ => return None,
    };
    Some(now - delta)
}

impl Lanzou {
    pub fn new(cookie: String, account: String, password: String) -> Self {
        Lanzou {
            http: Client::new(),
            http_no_redirect: ClientBuilder::new()
                .redirect(redirect::Policy::none())
                .build()
                .unwrap(),
            cookie: Mutex::new(cookie),
            uid: Mutex::new(String::new()),
            vei: Mutex::new(String::new()),
            account,
            password,
        }
    }

    fn cookie(&self) -> String {
        self.cookie.lock().unwrap().clone()
    }

    fn is_account(&self) -> bool {
        !self.account.is_empty()
    }

    /// 对齐 Login()：账号密码登录 up.woozooo.com/mlogin.php，成功后保存 cookie
    async fn login(&self) -> Result<(), String> {
        if !self.is_account() {
            return Err("蓝奏云账号为空".into());
        }
        let mut vs = String::new();
        for _ in 0..3 {
            let mut req = self
                .http_no_redirect
                .post(LOGIN_URL)
                .header("Referer", "https://pc.woozooo.com")
                .header("User-Agent", DEFAULT_UA)
                .form(&[
                    ("task".to_string(), "3".to_string()),
                    ("uid".to_string(), self.account.clone()),
                    ("pwd".to_string(), self.password.clone()),
                    ("setSessionId".to_string(), String::new()),
                    ("setSig".to_string(), String::new()),
                    ("setScene".to_string(), String::new()),
                    ("setTocen".to_string(), String::new()),
                    ("formhash".to_string(), String::new()),
                ]);
            if !vs.is_empty() {
                req = req.header("cookie", format!("acw_sc__v2={vs}"));
            }
            let resp = req
                .send()
                .await
                .map_err(|e| format!("蓝奏云登录请求失败: {e}"))?;
            // 先取 set-cookie 再读 body（text() 会消费响应）
            let cookies: Vec<String> = resp
                .headers()
                .get_all("set-cookie")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .filter_map(|c| c.split(';').next())
                .filter(|kv| {
                    let kv = kv.trim();
                    !kv.is_empty() && kv.contains('=')
                })
                .map(|kv| kv.trim().to_string())
                .collect();
            let body = resp
                .text()
                .await
                .map_err(|e| format!("读取响应失败: {e}"))?;
            if body.contains("acw_sc__v2") {
                vs = calc_acw_sc_v2(&body)?;
                continue;
            }
            let v: Value =
                serde_json::from_str(&body).map_err(|e| format!("蓝奏云登录响应解析失败: {e}"))?;
            if v.get("zt").and_then(|x| x.as_i64()) != Some(1) {
                let info = v.get("info").and_then(|x| x.as_str()).unwrap_or("未知错误");
                return Err(format!("蓝奏云登录失败: {info}"));
            }
            *self.cookie.lock().unwrap() = cookies.join("; ");
            return Ok(());
        }
        Err("蓝奏云登录 acw_sc__v2 验证失败".into())
    }

    /// 统一请求：自动处理 acw_sc__v2 验证页与 down_ip=1（对齐 request()）
    async fn request(
        &self,
        method: Method,
        url: &str,
        form: Option<&[(String, String)]>,
        with_down_ip: bool,
    ) -> Result<String, String> {
        let mut vs = String::new();
        for _ in 0..3 {
            let mut req = self
                .http
                .request(method.clone(), url)
                .header("Referer", "https://pc.woozooo.com")
                .header("User-Agent", DEFAULT_UA);
            let mut cookie = String::new();
            if with_down_ip {
                cookie = if !self.cookie().is_empty() {
                    format!("{}; down_ip=1", self.cookie())
                } else {
                    "down_ip=1".to_string()
                };
            } else if !self.cookie().is_empty() {
                cookie = self.cookie();
            }
            if !vs.is_empty() {
                if cookie.is_empty() {
                    cookie = format!("acw_sc__v2={vs}");
                } else {
                    cookie = format!("{cookie}; acw_sc__v2={vs}");
                }
            }
            if !cookie.is_empty() {
                req = req.header("cookie", cookie);
            }
            if let Some(f) = form {
                req = req.form(f);
            }
            let resp = req.send().await.map_err(|e| format!("请求失败: {e}"))?;
            let body = resp
                .text()
                .await
                .map_err(|e| format!("读取响应失败: {e}"))?;
            if body.contains("acw_sc__v2") {
                vs = calc_acw_sc_v2(&body)?;
                continue;
            }
            return Ok(body);
        }
        Err("acw_sc__v2 验证失败".into())
    }

    /// 对齐 doupload()：POST /doupload.php?uid=&vei=，检查 zt；
    /// account 模式下 zt=9（登录过期）自动重登后重试一次（对齐 post()）
    async fn doupload(
        &self,
        form: &[(String, String)],
        with_down_ip: bool,
    ) -> Result<Value, String> {
        let mut retried = false;
        let mut busy_retries = 0;
        loop {
            let url = format!(
                "{BASE_URL}/doupload.php?uid={}&vei={}",
                self.uid.lock().unwrap(),
                self.vei.lock().unwrap()
            );
            let body = self
                .request(Method::POST, &url, Some(form), with_down_ip)
                .await?;
            let v: Value =
                serde_json::from_str(&body).map_err(|e| format!("蓝奏云响应解析失败: {e}"))?;
            let zt = v.get("zt").and_then(|x| x.as_i64()).unwrap_or(-1);
            match zt {
                1 | 2 => return Ok(v),
                // 接口繁忙：等 1 秒重试（对齐 Go 版 resty 重试条件）
                4 => {
                    busy_retries += 1;
                    if busy_retries < 3 {
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        continue;
                    }
                    return Ok(v);
                }
                9 => {
                    if self.is_account() && !retried {
                        retried = true;
                        self.login().await?;
                        continue;
                    }
                    return Err("蓝奏云登录已过期（cookie 失效）".into());
                }
                _ => {
                    let info = v
                        .get("inf")
                        .or_else(|| v.get("info"))
                        .and_then(|x| x.as_str())
                        .unwrap_or("unknown")
                        .to_string();
                    return Err(format!("蓝奏云接口错误(zt={zt}): {info}"));
                }
            }
        }
    }

    /// 对齐 Init()：account 模式先登录，再从 mydisk.php 取 uid / vei
    pub async fn validate(&self) -> Result<(), String> {
        if self.is_account() {
            self.login().await?;
        } else if self.cookie().is_empty() {
            return Err("蓝奏云需要账号密码或 cookie".into());
        }
        let url = format!("{BASE_URL}/mydisk.php?item=files&action=index");
        let html = self.request(Method::GET, &url, None, false).await?;
        // uid
        let uid_re = Regex::new(r#"uid=([^'"&;]+)"#).unwrap();
        let uid = uid_re
            .captures(&html)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
            .ok_or("蓝奏云页面未找到 uid（cookie 可能已失效）")?;
        // vei
        let cleaned = remove_notes(&html);
        let kvs = html_json_to_map(&cleaned)?;
        let vei = kvs
            .iter()
            .find(|(k, _)| k == "vei")
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        *self.uid.lock().unwrap() = uid;
        *self.vei.lock().unwrap() = vei;
        Ok(())
    }

    /// 对齐 GetAllFiles()：task=47 文件夹 + task=5 文件分页
    pub async fn list(&self, folder_id: &str) -> Result<Vec<Entry>, String> {
        // 根目录为 "-1"（Go 版 DefaultRoot）；旧配置里可能存了兜底值 "0"
        let fid = if folder_id.is_empty() || folder_id == "0" {
            "-1"
        } else {
            folder_id
        };
        // 文件夹
        let mut files = Vec::new();
        let resp = self
            .doupload(
                &[
                    ("task".into(), "47".into()),
                    ("folder_id".into(), fid.to_string()),
                ],
                false,
            )
            .await?;
        if let Some(text) = resp.get("text").and_then(|x| x.as_array()) {
            for f in text {
                let fol_id = f
                    .get("fol_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let name = f
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let time = f
                    .get("time")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                files.push(Entry {
                    fid: fol_id.clone(),
                    name,
                    size: 0,
                    is_dir: !fol_id.is_empty(),
                    updated_at: parse_time_to_ms(&time),
                    etag: None,
                    s3_key_flag: None,
                    file_type: None,
                    extra: None,
                });
            }
        }
        // 文件（分页）
        let mut pg = 1;
        loop {
            let resp = self
                .doupload(
                    &[
                        ("task".into(), "5".into()),
                        ("folder_id".into(), fid.to_string()),
                        ("pg".into(), pg.to_string()),
                    ],
                    false,
                )
                .await?;
            let text = resp
                .get("text")
                .and_then(|x| x.as_array())
                .cloned()
                .unwrap_or_default();
            if text.is_empty() {
                break;
            }
            for f in &text {
                let id = f
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let name = f
                    .get("name_all")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let size = f
                    .get("size")
                    .and_then(|v| v.as_str())
                    .map(size_str_to_u64)
                    .unwrap_or(0);
                let time = f
                    .get("time")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                files.push(Entry {
                    fid: id,
                    name,
                    size,
                    is_dir: false,
                    updated_at: parse_time_to_ms(&time),
                    etag: None,
                    s3_key_flag: None,
                    file_type: None,
                    extra: None,
                });
            }
            pg += 1;
        }
        Ok(files)
    }

    /// 对齐 Link()：task=22 取分享信息 -> 分享页 -> 直链
    pub async fn download(&self, e: &Entry) -> Result<DownloadInfo, String> {
        // 1. 取文件分享地址（f_id = 分享页 id，pwd = 提取码）
        let resp = self
            .doupload(
                &[
                    ("task".into(), "22".into()),
                    ("file_id".into(), e.fid.to_string()),
                ],
                false,
            )
            .await?;
        let share_id = resp
            .pointer("/info/f_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let pwd = resp
            .pointer("/info/pwd")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if share_id.is_empty() {
            return Err("蓝奏云未取到文件分享信息".into());
        }
        // 2. 解析分享页拿直链
        let url = self.get_files_by_share_url(&share_id, &pwd).await?;
        Ok(DownloadInfo {
            url,
            headers: vec![("User-Agent".into(), DEFAULT_UA.into())],
            proxy: true,
            local_path: None,
        })
    }

    /// 对齐 getShareUrlHtml()
    async fn get_share_url_html(&self, share_id: &str) -> Result<String, String> {
        let mut vs = String::new();
        for _ in 0..3 {
            let url = format!("{SHARE_URL}/{share_id}");
            // 对齐 Go 版 d.get：同样携带蓝奏云 cookie
            let mut cookie = self.cookie();
            if !vs.is_empty() {
                cookie = if cookie.is_empty() {
                    format!("acw_sc__v2={vs}")
                } else {
                    format!("{cookie}; acw_sc__v2={vs}")
                };
            }
            let mut req = self
                .http
                .get(&url)
                .header("User-Agent", DEFAULT_UA)
                .header("Referer", "https://pc.woozooo.com");
            if !cookie.is_empty() {
                req = req.header("cookie", cookie);
            }
            let resp = req.send().await.map_err(|e| format!("请求失败: {e}"))?;
            let body = resp
                .text()
                .await
                .map_err(|e| format!("读取响应失败: {e}"))?;
            let page = remove_notes(&body);
            if page.contains("取消分享") {
                return Err("蓝奏云：文件已取消分享".into());
            }
            if page.contains("文件不存在") {
                return Err("蓝奏云：文件不存在".into());
            }
            if page.contains("acw_sc__v2") {
                vs = calc_acw_sc_v2(&body)?;
                continue;
            }
            return Ok(page);
        }
        Err("acw_sc__v2 验证失败".into())
    }

    /// 对齐 GetFilesByShareUrl()：解析分享页/下载页 -> 真实直链
    async fn get_files_by_share_url(&self, share_id: &str, pwd: &str) -> Result<String, String> {
        let page_data = self.get_share_url_html(share_id).await?;
        let base_url;

        let need_pwd = page_data.contains("pwdload") || page_data.contains("passwddiv");
        let download_url = if need_pwd {
            let func = get_js_function_by_name(&page_data, "down_p")?;
            let mut param = html_json_to_map(&func)?;
            // 覆盖 p = 提取码
            param.retain(|(k, _)| k != "p");
            param.push(("p".to_string(), pwd.to_string()));
            let id_re = Regex::new(r"'/ajax(?:file|m)\.php\?file=(\d+)'").unwrap();
            let full = id_re
                .find(&page_data)
                .map(|m| m.as_str().to_string())
                .ok_or("蓝奏云：未找到文件 id")?;
            // 去掉首尾引号
            let path = full.trim_matches('\'');
            let ajax_url = format!("{SHARE_URL}{path}");
            let resp = self
                .request(Method::POST, &ajax_url, Some(&param), false)
                .await?;
            let v: Value = serde_json::from_str(&resp)
                .map_err(|e| format!("蓝奏云 ajax 响应解析失败: {e}"))?;
            let dom = v.get("dom").and_then(|x| x.as_str()).unwrap_or("");
            let url = v.get("url").and_then(|x| x.as_str()).unwrap_or("");
            base_url = format!("{dom}/file");
            format!("{base_url}/{url}")
        } else {
            // 取下载页 iframe 参数
            let iframe_re = Regex::new(r#"<iframe.*?src="(.+?)""#).unwrap();
            let urlpath = iframe_re
                .captures(&page_data)
                .and_then(|c| c.get(1))
                .map(|m| m.as_str().to_string())
                .ok_or("蓝奏云：未找到下载页参数")?;
            let url2 = format!("{SHARE_URL}{urlpath}");
            let data = self.request(Method::GET, &url2, None, false).await?;
            let next_page = remove_notes(&data);
            let form_pairs = html_json_to_map(&next_page)?;
            let id_re = Regex::new(r"'/ajax(?:file|m)\.php\?file=(\d+)'").unwrap();
            let full = id_re
                .find(&next_page)
                .map(|m| m.as_str().to_string())
                .ok_or("蓝奏云：未找到文件 id")?;
            let path = full.trim_matches('\'');
            let ajax_url = format!("{SHARE_URL}{path}");
            let resp = self
                .request(Method::POST, &ajax_url, Some(&form_pairs), false)
                .await?;
            let v: Value = serde_json::from_str(&resp)
                .map_err(|e| format!("蓝奏云 ajax 响应解析失败: {e}"))?;
            let dom = v.get("dom").and_then(|x| x.as_str()).unwrap_or("");
            let url = v.get("url").and_then(|x| x.as_str()).unwrap_or("");
            base_url = format!("{dom}/file");
            format!("{base_url}/{url}")
        };

        // 跟随 302 拿真实链接（带 down_ip=1）
        let mut vs = String::new();
        let mut location = String::new();
        let mut body_str = String::new();
        let mut is_302 = false;
        for _ in 0..3 {
            let mut req = self
                .http_no_redirect
                .get(&download_url)
                .header(
                    "accept-language",
                    "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
                )
                .header("Referer", &base_url)
                .header("User-Agent", DEFAULT_UA)
                .header("cookie", "down_ip=1");
            if !vs.is_empty() {
                req = req.header("cookie", format!("down_ip=1; acw_sc__v2={vs}"));
            }
            let resp = req.send().await.map_err(|e| format!("获取直链失败: {e}"))?;
            let status = resp.status().as_u16();
            if status == 302 {
                location = resp
                    .headers()
                    .get("location")
                    .and_then(|l| l.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                is_302 = true;
                break;
            }
            let body = resp
                .text()
                .await
                .map_err(|e| format!("读取响应失败: {e}"))?;
            if body.contains("acw_sc__v2") {
                vs = calc_acw_sc_v2(&body)?;
                continue;
            }
            body_str = body;
            break;
        }

        if !is_302 {
            // 触发二次验证：el=2 再请求一次 ajax
            let mut param = html_json_to_map(&remove_js_comment(&body_str))?;
            param.retain(|(k, _)| k != "el");
            param.push(("el".to_string(), "2".to_string()));
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            let mut data = String::new();
            for _ in 0..3 {
                let mut cookie = "down_ip=1".to_string();
                if !vs.is_empty() {
                    cookie = format!("down_ip=1; acw_sc__v2={vs}");
                }
                let resp = self
                    .http
                    .post(format!("{base_url}/ajax.php"))
                    .form(&param)
                    .header("User-Agent", DEFAULT_UA)
                    .header("cookie", cookie)
                    .send()
                    .await
                    .map_err(|e| format!("二次验证请求失败: {e}"))?;
                let body = resp
                    .text()
                    .await
                    .map_err(|e| format!("读取响应失败: {e}"))?;
                if body.contains("acw_sc__v2") {
                    vs = calc_acw_sc_v2(&body)?;
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    continue;
                }
                data = body;
                break;
            }
            if data.is_empty() {
                return Err("蓝奏云二次验证失败".into());
            }
            let v: Value = serde_json::from_str(&data)
                .map_err(|e| format!("蓝奏云二次验证响应解析失败: {e}"))?;
            location = v
                .get("url")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
        }

        if location.is_empty() {
            return Err("蓝奏云未获取到下载直链".into());
        }
        Ok(location)
    }

    // ---------- 写操作（对齐 Go 版 MakeDir/Rename/Move/Remove/Put） ----------

    /// 写操作前置检查（对齐 Go 版各写方法里的 IsCookie() || IsAccount() 判断）
    fn require_auth(&self) -> Result<(), String> {
        if self.is_account() || !self.cookie().is_empty() {
            Ok(())
        } else {
            Err("蓝奏云需要账号密码或 cookie".into())
        }
    }

    /// 对齐 MakeDir()：doupload task=2 新建文件夹
    pub async fn mkdir(&self, parent_fid: &str, name: &str) -> Result<(), String> {
        self.require_auth()?;
        self.doupload(
            &[
                ("task".into(), "2".into()),
                ("parent_id".into(), parent_fid.to_string()),
                ("folder_name".into(), name.to_string()),
                ("folder_description".into(), String::new()),
            ],
            false,
        )
        .await?;
        Ok(())
    }

    /// 对齐 Rename()：doupload task=46 + type=2 重命名（Go 版仅支持文件）
    pub async fn rename(&self, _parent_fid: &str, e: &Entry, new_name: &str) -> Result<(), String> {
        self.require_auth()?;
        if e.is_dir {
            return Err("蓝奏云 不支持重命名文件夹操作".into());
        }
        self.doupload(
            &[
                ("task".into(), "46".into()),
                ("file_id".into(), e.fid.to_string()),
                ("file_name".into(), new_name.to_string()),
                ("type".into(), "2".into()),
            ],
            false,
        )
        .await?;
        Ok(())
    }

    /// 对齐 Move()：doupload task=20 移动文件（Go 版仅支持文件，文件夹返回 NotSupport）
    pub async fn move_entry(
        &self,
        _parent_fid: &str,
        e: &Entry,
        dst_dir_fid: &str,
    ) -> Result<(), String> {
        self.require_auth()?;
        if e.is_dir {
            return Err("蓝奏云 不支持移动文件夹操作".into());
        }
        self.doupload(
            &[
                ("task".into(), "20".into()),
                ("folder_id".into(), dst_dir_fid.to_string()),
                ("file_id".into(), e.fid.to_string()),
            ],
            false,
        )
        .await?;
        Ok(())
    }

    /// 对齐 Copy()：Go 版蓝奏云驱动没有 Copy 实现
    pub async fn copy(
        &self,
        _parent_fid: &str,
        _e: &Entry,
        _dst_dir_fid: &str,
    ) -> Result<(), String> {
        Err("蓝奏云 不支持复制操作".into())
    }

    /// 对齐 Remove()：doupload task=3 删文件夹 / task=6 删文件
    pub async fn remove(&self, _parent_fid: &str, e: &Entry) -> Result<(), String> {
        self.require_auth()?;
        let form = if e.is_dir {
            vec![
                ("task".to_string(), "3".to_string()),
                ("folder_id".to_string(), e.fid.to_string()),
            ]
        } else {
            vec![
                ("task".to_string(), "6".to_string()),
                ("file_id".to_string(), e.fid.to_string()),
            ]
        };
        self.doupload(&form, false).await?;
        Ok(())
    }

    /// 对齐 Put()：POST /html5up.php multipart 上传
    /// 字段对齐 Go 版：task=1, vie=2, ve=2, id=WU_FILE_0, name, folder_id_bb_n
    /// + 文件域 upload_file（resty SetFileReader，Content-Type 固定 application/octet-stream）
    ///
    /// reader 只能读一次，而 acw_sc__v2 验证页可能要求整体重发请求，
    /// 因此先把完整 multipart body 落临时文件（可重复读、可算 Content-Length，
    /// 对齐 Go 版 resty 缓冲 body 的行为），结束（含出错路径）时删除。
    pub async fn put(&self, dst_dir_fid: &str, mut input: super::PutInput) -> Result<(), String> {
        use tokio::io::AsyncWriteExt;
        self.require_auth()?;

        // 1. 手工构造 multipart/form-data（reqwest 未启用 multipart 特性）
        let boundary = uuid::Uuid::new_v4().simple().to_string();
        let mut fields = String::new();
        for (k, v) in [
            ("task", "1"),
            ("vie", "2"),
            ("ve", "2"),
            ("id", "WU_FILE_0"),
            ("name", input.name.as_str()),
            ("folder_id_bb_n", dst_dir_fid),
        ] {
            fields.push_str(&format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n"
            ));
        }
        // 对齐 Go mime/multipart 的 escapeQuotes：仅转义反斜杠与引号
        let filename = input.name.replace('\\', "\\\\").replace('"', "\\\"");
        let head = format!(
            "{fields}--{boundary}\r\nContent-Disposition: form-data; name=\"upload_file\"; filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        );
        let tail = format!("\r\n--{boundary}--\r\n");

        let tmp_path =
            std::env::temp_dir().join(format!("openlist-lanzou-{}.part", uuid::Uuid::new_v4()));
        let _tmp_guard = TempFileGuard(tmp_path.clone());

        let mut body_file = tokio::fs::File::create(&tmp_path)
            .await
            .map_err(|e| format!("创建蓝奏云上传临时文件失败: {e}"))?;
        body_file
            .write_all(head.as_bytes())
            .await
            .map_err(|e| format!("写入蓝奏云上传临时文件失败: {e}"))?;
        let n = tokio::io::copy(&mut input.reader, &mut body_file)
            .await
            .map_err(|e| format!("读取上传内容失败: {e}"))?;
        body_file
            .write_all(tail.as_bytes())
            .await
            .map_err(|e| format!("写入蓝奏云上传临时文件失败: {e}"))?;
        body_file
            .flush()
            .await
            .map_err(|e| format!("写入蓝奏云上传临时文件失败: {e}"))?;
        drop(body_file);
        let content_length = head.len() as u64 + n + tail.len() as u64;

        // 2. 上传：外层 zt=4 繁忙重试（对齐 _post 的 resty 重试条件），
        //    内层 acw_sc__v2 验证页重试（对齐 request()），均从临时文件重放 body
        let url = format!("{BASE_URL}/html5up.php");
        let mut busy_retries = 0;
        loop {
            let mut vs = String::new();
            let mut last_body = String::new();
            let mut acw_ok = false;
            for _ in 0..3 {
                let file = tokio::fs::File::open(&tmp_path)
                    .await
                    .map_err(|e| format!("读取蓝奏云上传临时文件失败: {e}"))?;
                use tokio_util::io::ReaderStream;
                let mut req = self
                    .http
                    .post(&url)
                    .header("Referer", "https://pc.woozooo.com")
                    .header("User-Agent", DEFAULT_UA)
                    .header(
                        "Content-Type",
                        format!("multipart/form-data; boundary={boundary}"),
                    )
                    .header("Content-Length", content_length.to_string())
                    .body(reqwest::Body::wrap_stream(ReaderStream::with_capacity(
                        file,
                        64 * 1024,
                    )));
                // 对齐 request() 的 cookie 逻辑：html5up.php 不含 /file/，不带 down_ip
                let mut cookie = self.cookie();
                if !vs.is_empty() {
                    cookie = if cookie.is_empty() {
                        format!("acw_sc__v2={vs}")
                    } else {
                        format!("{cookie}; acw_sc__v2={vs}")
                    };
                }
                if !cookie.is_empty() {
                    req = req.header("cookie", cookie);
                }
                let resp = req
                    .send()
                    .await
                    .map_err(|e| format!("蓝奏云上传请求失败: {e}"))?;
                let body_text = resp
                    .text()
                    .await
                    .map_err(|e| format!("读取响应失败: {e}"))?;
                if body_text.contains("acw_sc__v2") {
                    vs = calc_acw_sc_v2(&body_text)?;
                    continue;
                }
                last_body = body_text;
                acw_ok = true;
                break;
            }
            if !acw_ok {
                return Err("acw_sc__v2 验证失败".into());
            }
            // 对齐 _post() 的 zt 判断：1/2/4 成功，9 登录过期，其余取 inf/info 报错
            let v: Value = serde_json::from_str(&last_body)
                .map_err(|e| format!("蓝奏云上传响应解析失败: {e}"))?;
            let zt = v.get("zt").and_then(|x| x.as_i64()).unwrap_or(-1);
            match zt {
                1 | 2 => return Ok(()),
                4 => {
                    busy_retries += 1;
                    if busy_retries < 3 {
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        continue;
                    }
                    return Ok(());
                }
                9 => return Err("蓝奏云登录已过期（cookie 失效）".into()),
                _ => {
                    let info = v
                        .get("inf")
                        .or_else(|| v.get("info"))
                        .and_then(|x| x.as_str())
                        .unwrap_or("unknown")
                        .to_string();
                    return Err(format!("蓝奏云接口错误(zt={zt}): {info}"));
                }
            }
        }
    }
}

/// 临时文件守卫：drop 时删除（对齐 Go 版 defer os.Remove 语义）
struct TempFileGuard(std::path::PathBuf);

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_size_parse() {
        assert_eq!(size_str_to_u64("2.4 M"), 2_516_582);
        assert_eq!(size_str_to_u64("512 K"), 524_288);
        assert_eq!(size_str_to_u64("100 B"), 100);
    }

    #[test]
    fn test_acw() {
        // 真实挑战页 arg1 为 40 位十六进制；期望值按 Go 版 CalcAcwScV2 同步计算
        let r = calc_acw_sc_v2("var arg1='A55A97B1D9526B15C2189E7A5D9BAF16A55A97B1';");
        assert!(r.is_ok());
        assert_eq!(r.unwrap(), "25aab2c79d9479e15060b3d2896e36baeedb5a5f");
    }

    #[test]
    fn test_remove_js_comment() {
        assert_eq!(remove_js_comment("a//hello\nb"), "a\nb");
        assert_eq!(remove_js_comment("a/*x*/b"), "ab");
        // 中文不受影响
        assert_eq!(remove_js_comment("文件描述//x\ny"), "文件描述\ny");
    }
}
