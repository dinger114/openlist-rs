//! PikPak 分享驱动（对齐 Go 版 drivers/pikpak_share，只读）
//!
//! - 凭据：share_id + 可选 share_pwd；platform = android/web/pc
//! - 初始化：刷新 captcha_token，有密码时换 pass_code_token
//! - 列表：GET /drive/v1/share/detail
//! - 下载：GET /drive/v1/share/file_info → web_content_link / medias

use super::{DownloadInfo, PutInput};
use crate::config::Entry;
use md5::Digest;
use reqwest::Client;
use serde_json::{json, Value};
use std::sync::Mutex;
use uuid::Uuid;

const DRIVE_API: &str = "https://api-drive.mypikpak.net";
const USER_API: &str = "https://user.mypikpak.net";

const WEB_CLIENT_ID: &str = "YUMx5nI8ZU8Ap8pm";
const WEB_CLIENT_VERSION: &str = "2.0.0";
const WEB_PACKAGE: &str = "mypikpak.com";
const WEB_ALGORITHMS: [&str; 15] = [
    "C9qPpZLN8ucRTaTiUMWYS9cQvWOE",
    "+r6CQVxjzJV6LCV",
    "F",
    "pFJRC",
    "9WXYIDGrwTCz2OiVlgZa90qpECPD6olt",
    "/750aCr4lm/Sly/c",
    "RB+DT/gZCrbV",
    "",
    "CyLsf7hdkIRxRm215hl",
    "7xHvLi2tOYP0Y92b",
    "ZGTXXxu8E/MIWaEDB+Sm/",
    "1UI3",
    "E7fP5Pfijd+7K+t6Tg/NhuLq0eEUVChpJSkrKxpO",
    "ihtqpG6FMt65+Xk+tWUH2",
    "NhXXU9rg4XXdzo7u5o",
];

const ANDROID_CLIENT_ID: &str = "YNxT9w7GMdWvEOKa";
const ANDROID_CLIENT_VERSION: &str = "1.53.2";
const ANDROID_PACKAGE: &str = "com.pikcloud.pikpak";
const ANDROID_ALGORITHMS: [&str; 8] = [
    "SOP04dGzk0TNO7t7t9ekDbAmx+eq0OI1ovEx",
    "nVBjhYiND4hZ2NCGyV5beamIr7k6ifAsAbl",
    "Ddjpt5B/Cit6EDq2a6cXgxY9lkEIOw4yC1GDF28KrA",
    "VVCogcmSNIVvgV6U+AochorydiSymi68YVNGiz",
    "u5ujk5sM62gpJOsB/1Gu/zsfgfZO",
    "dXYIiBOAHZgzSruaQ2Nhrqc2im",
    "z5jUTBSIpBN9g4qSJGlidNAutX6",
    "KJE2oveZ34du/g1tiimm",
];

const PC_CLIENT_ID: &str = "YvtoWO6GNHiuCl7x";
const PC_CLIENT_VERSION: &str = "undefined";
const PC_PACKAGE: &str = "mypikpak.com";
const PC_ALGORITHMS: [&str; 10] = [
    "KHBJ07an7ROXDoK7Db",
    "G6n399rSWkl7WcQmw5rpQInurc1DkLmLJqE",
    "JZD1A3M4x+jBFN62hkr7VDhkkZxb9g3rWqRZqFAAb",
    "fQnw/AmSlbbI91Ik15gpddGgyU7U",
    "/Dv9JdPYSj3sHiWjouR95NTQff",
    "yGx2zuTjbWENZqecNI+edrQgqmZKP",
    "ljrbSzdHLwbqcRn",
    "lSHAsqCkGDGxQqqwrVu",
    "TsWXI81fD1",
    "vk7hBjawK/rOSrSWajtbMk95nfgf3",
];

fn md5_hex(s: &str) -> String {
    let mut h = md5::Md5::new();
    h.update(s.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

struct PlatformCfg {
    client_id: &'static str,
    client_version: &'static str,
    package_name: &'static str,
    algorithms: &'static [&'static str],
    user_agent: &'static str,
}

fn platform_cfg(platform: &str) -> PlatformCfg {
    match platform {
        "android" => PlatformCfg {
            client_id: ANDROID_CLIENT_ID,
            client_version: ANDROID_CLIENT_VERSION,
            package_name: ANDROID_PACKAGE,
            algorithms: &ANDROID_ALGORITHMS,
            user_agent: "android-com.pikcloud.pikpak/1.53.2",
        },
        "pc" => PlatformCfg {
            client_id: PC_CLIENT_ID,
            client_version: PC_CLIENT_VERSION,
            package_name: PC_PACKAGE,
            algorithms: &PC_ALGORITHMS,
            user_agent: "MainWindow Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) PikPak/2.6.11.4955 Chrome/100.0.4896.160 Electron/18.3.15 Safari/537.36",
        },
        _ => PlatformCfg {
            client_id: WEB_CLIENT_ID,
            client_version: WEB_CLIENT_VERSION,
            package_name: WEB_PACKAGE,
            algorithms: &WEB_ALGORITHMS,
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
        },
    }
}

pub struct PikPakShare {
    share_id: String,
    share_pwd: String,
    platform: String,
    device_id: String,
    use_transcoding: bool,
    http: Client,
    captcha_token: Mutex<String>,
    pass_code_token: Mutex<String>,
}

impl PikPakShare {
    pub fn new(
        share_id: String,
        share_pwd: String,
        platform: String,
        device_id: String,
        use_transcoding: bool,
    ) -> Self {
        let device_id = if device_id.trim().is_empty() {
            Uuid::new_v4().to_string().replace('-', "")
        } else {
            device_id
        };
        let platform = if platform.trim().is_empty() {
            "web".into()
        } else {
            platform
        };
        PikPakShare {
            share_id,
            share_pwd,
            platform,
            device_id,
            use_transcoding,
            http: Client::new(),
            captcha_token: Mutex::new(String::new()),
            pass_code_token: Mutex::new(String::new()),
        }
    }

    fn captcha_sign(&self) -> (String, String) {
        let cfg = platform_cfg(&self.platform);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
            .to_string();
        let mut str_ = format!(
            "{}{}{}{}{}",
            cfg.client_id, cfg.client_version, cfg.package_name, self.device_id, timestamp
        );
        for algo in cfg.algorithms {
            str_ = md5_hex(&format!("{str_}{algo}"));
        }
        (timestamp, format!("1.{str_}"))
    }

    async fn refresh_captcha(&self, action: &str) -> Result<(), String> {
        let cfg = platform_cfg(&self.platform);
        let (timestamp, captcha_sign) = self.captcha_sign();
        let body = json!({
            "action": action,
            "captcha_token": self.captcha_token.lock().unwrap().clone(),
            "client_id": cfg.client_id,
            "device_id": self.device_id,
            "meta": {
                "client_version": cfg.client_version,
                "package_name": cfg.package_name,
                "user_id": "",
                "timestamp": timestamp,
                "captcha_sign": captcha_sign,
            }
        });
        let resp = self
            .http
            .post(format!("{USER_API}/v1/shield/captcha/init"))
            .header("User-Agent", cfg.user_agent)
            .header("X-Client-ID", cfg.client_id)
            .header("X-Device-ID", &self.device_id)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("PikPakShare captcha: {e}"))?;
        let text = resp.text().await.unwrap_or_default();
        let v: Value = serde_json::from_str(&text).unwrap_or(json!({}));
        if let Some(code) = v.get("error_code").and_then(|c| c.as_i64()) {
            if code != 0 {
                return Err(format!(
                    "PikPakShare captcha 失败: {}",
                    v.get("error_description")
                        .or_else(|| v.get("error"))
                        .and_then(|e| e.as_str())
                        .unwrap_or(&text)
                ));
            }
        }
        let token = v
            .get("captcha_token")
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .to_string();
        if token.is_empty() {
            return Err(format!("PikPakShare 无 captcha_token: {text}"));
        }
        *self.captcha_token.lock().unwrap() = token;
        Ok(())
    }

    async fn get_pass_token(&self) -> Result<(), String> {
        if self.share_pwd.is_empty() {
            return Ok(());
        }
        let cfg = platform_cfg(&self.platform);
        let body = json!({
            "share_id": self.share_id,
            "pass_code": self.share_pwd,
        });
        let captcha = self.captcha_token.lock().unwrap().clone();
        let resp = self
            .http
            .post(format!("{DRIVE_API}/drive/v1/share/pass_code"))
            .header("User-Agent", cfg.user_agent)
            .header("X-Client-ID", cfg.client_id)
            .header("X-Device-ID", &self.device_id)
            .header("X-Captcha-Token", &captcha)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("PikPakShare pass_code: {e}"))?;
        let text = resp.text().await.unwrap_or_default();
        let v: Value = serde_json::from_str(&text).unwrap_or(json!({}));
        if let Some(code) = v.get("error_code").and_then(|c| c.as_i64()) {
            if code != 0 {
                return Err(format!(
                    "PikPakShare 提取码错误: {}",
                    v.get("error_description")
                        .or_else(|| v.get("error"))
                        .and_then(|e| e.as_str())
                        .unwrap_or(&text)
                ));
            }
        }
        let token = v
            .get("pass_code_token")
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .to_string();
        *self.pass_code_token.lock().unwrap() = token;
        Ok(())
    }

    async fn request(&self, method: &str, url: &str, body: Option<Value>) -> Result<Value, String> {
        let cfg = platform_cfg(&self.platform);
        let captcha = self.captcha_token.lock().unwrap().clone();
        let mut req = match method {
            "POST" => self.http.post(url),
            _ => self.http.get(url),
        };
        req = req
            .header("User-Agent", cfg.user_agent)
            .header("X-Client-ID", cfg.client_id)
            .header("X-Device-ID", &self.device_id)
            .header("X-Captcha-Token", &captcha);
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| format!("PikPakShare 请求失败: {e}"))?;
        let text = resp.text().await.unwrap_or_default();
        let v: Value = serde_json::from_str(&text).unwrap_or(json!({}));
        let err_code = v.get("error_code").and_then(|c| c.as_i64()).unwrap_or(0);
        if err_code != 0 {
            return Err(format!(
                "PikPakShare 错误: {}",
                v.get("error_description")
                    .or_else(|| v.get("error"))
                    .and_then(|e| e.as_str())
                    .unwrap_or(&text)
            ));
        }
        Ok(v)
    }

    pub async fn validate(&self) -> Result<(), String> {
        if self.share_id.trim().is_empty() {
            return Err("PikPakShare share_id 不能为空".into());
        }
        let action = "GET:/drive/v1/share:batch_file_info";
        self.refresh_captcha(action).await?;
        self.get_pass_token().await?;
        let _ = self.list("").await?;
        Ok(())
    }

    fn root_id(fid: &str) -> String {
        let fid = fid.trim();
        if fid.is_empty() || fid == "0" || fid == "/" {
            String::new()
        } else {
            fid.trim_start_matches('/').to_string()
        }
    }

    pub async fn list(&self, parent_fid: &str) -> Result<Vec<Entry>, String> {
        let parent = Self::root_id(parent_fid);
        let mut out = Vec::new();
        let mut page_token = String::new();
        let mut pass_retried = false;
        loop {
            let pass = self.pass_code_token.lock().unwrap().clone();
            let mut url = format!(
                "{DRIVE_API}/drive/v1/share/detail?share_id={}&parent_id={}&limit=100&thumbnail_size=SIZE_LARGE&filters=%7B%22phase%22%3A%7B%22eq%22%3A%22PHASE_TYPE_COMPLETE%22%7D%2C%22trashed%22%3A%7B%22eq%22%3Afalse%7D%7D&pass_code_token={}",
                urlencoding_encode(&self.share_id),
                urlencoding_encode(&parent),
                urlencoding_encode(&pass),
            );
            if !page_token.is_empty() {
                url.push_str(&format!("&page_token={}", urlencoding_encode(&page_token)));
            }
            let v = self.request("GET", &url, None).await?;
            let status = v
                .get("share_status")
                .and_then(|s| s.as_str())
                .unwrap_or("OK");
            if status == "PASS_CODE_EMPTY" || status == "PASS_CODE_ERROR" {
                if pass_retried {
                    return Err(format!("PikPakShare 提取码无效: {status}"));
                }
                self.get_pass_token().await?;
                pass_retried = true;
                page_token.clear();
                out.clear();
                continue;
            }
            if status != "OK" && !status.is_empty() {
                let text = v
                    .get("share_status_text")
                    .and_then(|t| t.as_str())
                    .unwrap_or(status);
                return Err(format!("PikPakShare 状态: {text}"));
            }
            let files = v
                .get("files")
                .and_then(|f| f.as_array())
                .cloned()
                .unwrap_or_default();
            for f in files {
                let id = f
                    .get("id")
                    .and_then(|i| i.as_str())
                    .unwrap_or("")
                    .to_string();
                let name = f
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("")
                    .to_string();
                let kind = f.get("kind").and_then(|k| k.as_str()).unwrap_or("");
                let is_dir = kind == "drive#folder" || kind.contains("folder");
                let size: u64 = f
                    .get("size")
                    .and_then(|s| {
                        s.as_str()
                            .and_then(|x| x.parse().ok())
                            .or_else(|| s.as_u64())
                    })
                    .unwrap_or(0);
                if id.is_empty() || name.is_empty() {
                    continue;
                }
                out.push(Entry {
                    fid: id,
                    name,
                    size: if is_dir { 0 } else { size },
                    is_dir,
                    updated_at: None,
                    etag: None,
                    s3_key_flag: None,
                    file_type: None,
                    extra: None,
                });
            }
            page_token = v
                .get("next_page_token")
                .and_then(|t| t.as_str())
                .unwrap_or("")
                .to_string();
            if page_token.is_empty() {
                break;
            }
        }
        Ok(out)
    }

    pub async fn download(&self, e: &Entry) -> Result<DownloadInfo, String> {
        if e.is_dir {
            return Err("目录无法下载".into());
        }
        let pass = self.pass_code_token.lock().unwrap().clone();
        let url = format!(
            "{DRIVE_API}/drive/v1/share/file_info?share_id={}&file_id={}&pass_code_token={}",
            urlencoding_encode(&self.share_id),
            urlencoding_encode(&e.fid),
            urlencoding_encode(&pass),
        );
        let v = self.request("GET", &url, None).await?;
        let info = v.get("file_info").unwrap_or(&v);
        let mut link = info
            .get("web_content_link")
            .and_then(|u| u.as_str())
            .unwrap_or("")
            .to_string();
        if link.is_empty() {
            if let Some(medias) = info.get("medias").and_then(|m| m.as_array()) {
                if self.use_transcoding && medias.len() > 1 {
                    link = medias[1]
                        .pointer("/link/url")
                        .and_then(|u| u.as_str())
                        .unwrap_or("")
                        .to_string();
                } else if let Some(first) = medias.first() {
                    link = first
                        .pointer("/link/url")
                        .and_then(|u| u.as_str())
                        .unwrap_or("")
                        .to_string();
                }
            }
        }
        if link.is_empty() {
            return Err("PikPakShare 未返回下载链接".into());
        }
        Ok(DownloadInfo {
            url: link,
            headers: vec![],
            proxy: false,
            local_path: None,
        })
    }

    pub async fn mkdir(&self, _: &str, _: &str) -> Result<(), String> {
        Err("PikPak 分享为只读驱动，不支持此操作".into())
    }
    pub async fn rename(&self, _: &str, _: &Entry, _: &str) -> Result<(), String> {
        Err("PikPak 分享为只读驱动，不支持此操作".into())
    }
    pub async fn move_entry(&self, _: &str, _: &Entry, _: &str) -> Result<(), String> {
        Err("PikPak 分享为只读驱动，不支持此操作".into())
    }
    pub async fn copy(&self, _: &str, _: &Entry, _: &str) -> Result<(), String> {
        Err("PikPak 分享为只读驱动，不支持此操作".into())
    }
    pub async fn remove(&self, _: &str, _: &Entry) -> Result<(), String> {
        Err("PikPak 分享为只读驱动，不支持此操作".into())
    }
    pub async fn put(&self, _: &str, _: PutInput) -> Result<(), String> {
        Err("PikPak 分享为只读驱动，不支持此操作".into())
    }
}

fn urlencoding_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
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
