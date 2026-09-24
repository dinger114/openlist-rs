//! 迅雷网盘驱动（对齐 Go 版 drivers/thunder XunLeiCommon）
//!
//! - 授权：账号密码登录（v3 core login 换 sessionID -> signin/token 换令牌），
//!   或用已保存的 refresh_token 刷新
//! - 列目录：GET /drive/v1/files（page_token 分页）
//! - 下载：GET /drive/v1/files/{id} 取 web_content_link，访问需下载端 UA
//!
//! - 写操作：新建/重命名/移动/复制/删除走 /drive/v1/files 系列接口
//! - 上传：先落临时文件算 GCID（分块 sha1 的哈希再 sha1），POST /drive/v1/files
//!   创建任务（UPLOAD_TYPE_RESUMABLE）后经 S3 分片直传。依赖无 sha2/hmac
//!   crate，AWS SigV4 所需 SHA-256/HMAC 手写（对齐 pan115 手写 AES 的先例）
//!
//! 签名：captcha_sign = "1." + 对 (clientID+clientVersion+packageName+
//! deviceID+timestamp) 逐项追加 algorithms 后连续取 md5。

use super::DownloadInfo;
use crate::config::{Credential, Entry, Store};
use md5::Digest;
use reqwest::{Client, Method};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use uuid::Uuid;

const FILE_API_URL: &str = "https://api-pan.xunlei.com/drive/v1/files";
const XLUSER_API_URL: &str = "https://xluser-ssl.xunlei.com/v1";
const XLUSER_API_BASE_URL: &str = "https://xluser-ssl.xunlei.com";

// 上传（对齐 Go 版 drivers/thunder util.go 常量）
const FOLDER_KIND: &str = "drive#folder";
const FILE_KIND: &str = "drive#file";
const UPLOAD_TYPE_RESUMABLE: &str = "UPLOAD_TYPE_RESUMABLE";
// 对齐 s3manager.MaxUploadParts / DefaultUploadPartSize
const S3_MAX_PARTS: u64 = 10000;
const S3_DEFAULT_PART_SIZE: u64 = 5 * 1024 * 1024;
/// 对齐 Go aws.Config{Region: "xunlei"}
const S3_REGION: &str = "xunlei";

const CLIENT_ID: &str = "Xp6vsxz_7IYVw2BB";
const CLIENT_SECRET: &str = "Xp6vsy4tN9toTVdMSpomVdXpRmES";
const CLIENT_VERSION: &str = "8.31.0.9726";
const PACKAGE_NAME: &str = "com.xunlei.downloadprovider";
const USER_AGENT: &str = "ANDROID-com.xunlei.downloadprovider/8.31.0.9726 netWorkType/5G appid/40 deviceName/Xiaomi_M2004j7ac deviceModel/M2004J7AC OSVersion/12 protocolVersion/301 platformVersion/10 sdkVersion/512000 Oauth2Client/0.9 (Linux 4_14_186-perf-gddfs8vbb238b) (JAVA 0)";
const DOWNLOAD_USER_AGENT: &str =
    "Dalvik/2.1.0 (Linux; U; Android 12; M2004J7AC Build/SP1A.210812.016)";
const SIGN_PROVIDER: &str = "access_end_point_token";
const APPID: &str = "40";
const APP_KEY: &str = "34a062aaa22f906fca4fefe9fb3a3021";
/// 对齐 Go 版默认算法列表
const ALGORITHMS: [&str; 10] = [
    "9uJNVj/wLmdwKrJaVj/omlQ",
    "Oz64Lp0GigmChHMf/6TNfxx7O9PyopcczMsnf",
    "Eb+L7Ce+Ej48u",
    "jKY0",
    "ASr0zCl6v8W4aidjPK5KHd1Lq3t+vBFf41dqv5+fnOd",
    "wQlozdg6r1qxh0eRmt3QgNXOvSZO6q/GXK",
    "gmirk+ciAvIgA/cxUUCema47jr/YToixTT+Q6O",
    "5IiCoM9B1/788ntB",
    "P07JH0h6qoM6TSUAK2aL9T5s2QBVeY9JWvalf",
    "+oK0AN",
];

fn md5_hex(s: &str) -> String {
    let mut h = md5::Md5::new();
    h.update(s.as_bytes());
    hex(&h.finalize())
}

fn sha1_hex(s: &str) -> String {
    let mut h = sha1::Sha1::new();
    h.update(s.as_bytes());
    hex(&h.finalize())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// 对齐 generateDeviceSign()
fn generate_device_sign(device_id: &str, package_name: &str) -> String {
    let base = format!("{device_id}{package_name}{APPID}{APP_KEY}");
    let sha = sha1_hex(&base);
    let md5 = md5_hex(&sha);
    format!("div101.{device_id}{md5}")
}

/// 对齐 GetAction(): method + ":" + url 域名后的路径段
fn get_action(method: &str, url: &str) -> String {
    let idx = url.find("://").map(|i| i + 3).unwrap_or(0);
    let rest = &url[idx..];
    let path = match rest.split_once('/') {
        Some((_, p)) => format!("/{}", p.split(['?', '#']).next().unwrap_or("")),
        None => "/".to_string(),
    };
    format!("{method}:{path}")
}

#[derive(Debug, Clone, Default)]
struct TokenResp {
    token_type: String,
    access_token: String,
    refresh_token: String,
    user_id: String,
}

fn token_from(v: &Value) -> TokenResp {
    TokenResp {
        token_type: v
            .get("token_type")
            .and_then(|x| x.as_str())
            .unwrap_or("Bearer")
            .to_string(),
        access_token: v
            .get("access_token")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
        refresh_token: v
            .get("refresh_token")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
        user_id: v
            .get("user_id")
            .map(|x| match x {
                Value::String(s) => s.clone(),
                Value::Number(n) => n.to_string(),
                _ => String::new(),
            })
            .unwrap_or_default(),
    }
}

pub struct Thunder {
    account_id: String,
    http: Client,
    username: String,
    password: String,
    device_id: String,
    /// 构造时已保存的 refresh_token（首次 validate 时使用）
    saved_refresh: String,
    token: Mutex<Option<TokenResp>>,
    captcha_token: Mutex<String>,
    store: Arc<Store>,
}

impl Thunder {
    pub fn new(
        account_id: &str,
        username: String,
        password: String,
        refresh_token: String,
        captcha_token: String,
        device_id: String,
        store: Arc<Store>,
    ) -> Self {
        // 对齐 Init：device_id 缺省为 md5(username+password)
        let device_id = if device_id.len() == 32 {
            device_id
        } else {
            md5_hex(&format!("{username}{password}"))
        };
        Thunder {
            account_id: account_id.to_string(),
            http: Client::new(),
            username,
            password,
            device_id,
            saved_refresh: refresh_token,
            token: Mutex::new(None),
            captcha_token: Mutex::new(captcha_token),
            store,
        }
    }

    /// 持久化 refresh_token / captcha_token / device_id（空值不覆盖）
    fn save_credential(&self, refresh_token: &str, captcha_token: &str) {
        let id = self.account_id.clone();
        let (r, c) = (refresh_token.to_string(), captcha_token.to_string());
        let dev = self.device_id.clone();
        self.store.update_credential(&id, |cred| {
            if let Credential::Thunder {
                refresh_token,
                captcha_token,
                device_id,
                ..
            } = cred
            {
                if !r.is_empty() {
                    *refresh_token = r.clone();
                }
                if !c.is_empty() {
                    *captcha_token = c.clone();
                }
                *device_id = dev.clone();
            }
        });
    }

    /// 基础请求：公共头 + 错误码处理（对齐 Common.Request + XunLeiCommon.Request）
    async fn request(
        &self,
        method: Method,
        url: &str,
        query: Option<&[(String, String)]>,
        body: Option<Value>,
        auth: bool,
        retried: bool,
    ) -> Result<Value, String> {
        let mut req = self
            .http
            .request(method.clone(), url)
            .header("user-agent", USER_AGENT)
            .header("accept", "application/json;charset=UTF-8")
            .header("x-device-id", &self.device_id)
            .header("x-client-id", CLIENT_ID)
            .header("x-client-version", CLIENT_VERSION);
        if auth {
            let token = self.token.lock().unwrap().clone();
            let Some(t) = token else {
                return Err("迅雷未登录（token 为空）".into());
            };
            req = req
                .header(
                    "Authorization",
                    format!("{} {}", t.token_type, t.access_token),
                )
                .header(
                    "x-captcha-token",
                    self.captcha_token.lock().unwrap().clone(),
                );
        }
        if let Some(q) = query {
            req = req.query(q);
        }
        if let Some(b) = &body {
            req = req.json(b);
        }
        let resp = req.send().await.map_err(|e| format!("请求失败: {e}"))?;
        let v: Value = resp
            .json()
            .await
            .map_err(|e| format!("响应解析失败: {e}"))?;
        let err_code = v.get("error_code").and_then(|x| x.as_i64()).unwrap_or(0);
        let err_msg = v
            .get("error")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let is_error = err_msg != "success" && (err_code != 0 || !err_msg.is_empty());
        if is_error {
            if err_msg == "review_panel" {
                let creditkey = v
                    .get("creditkey")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                let reviewurl = v
                    .get("reviewurl")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                let sign = generate_device_sign(&self.device_id, PACKAGE_NAME);
                return Err(format!(
                    "迅雷本次登录需要验证，请在浏览器打开并完成验证后重试（creditkey={creditkey}）: {reviewurl}&deviceid={sign}"
                ));
            }
            if !retried {
                // 4122/4121/10/16: token 过期；9: captcha token 过期
                // 注意：request -> do_refresh_token -> login/_refresh_token -> request
                // 构成 async 递归环，所有环边均需 Box::pin 断开
                match err_code {
                    4122 | 4121 | 10 | 16 => {
                        Box::pin(self.do_refresh_token()).await?;
                        return Box::pin(self.request(method, url, query, body, auth, true)).await;
                    }
                    9 => {
                        let user_id = self
                            .token
                            .lock()
                            .unwrap()
                            .as_ref()
                            .map(|t| t.user_id.clone())
                            .unwrap_or_default();
                        let action = get_action(method.as_str(), url);
                        Box::pin(self.refresh_captcha_token_at_login(&action, &user_id)).await?;
                        return Box::pin(self.request(method, url, query, body, auth, true)).await;
                    }
                    _ => {}
                }
            }
            let desc = v
                .get("error_description")
                .and_then(|x| x.as_str())
                .unwrap_or("");
            return Err(format!("迅雷接口错误(code={err_code}): {err_msg} {desc}"));
        }
        Ok(v)
    }

    /// 对齐 GetCaptchaSign(): "1." + 连续 md5
    fn captcha_sign(&self) -> (String, String) {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
            .to_string();
        let mut str_val = format!(
            "{}{}{}{}{}",
            CLIENT_ID, CLIENT_VERSION, PACKAGE_NAME, self.device_id, timestamp
        );
        for algo in ALGORITHMS {
            str_val = md5_hex(&format!("{str_val}{algo}"));
        }
        (timestamp, format!("1.{str_val}"))
    }

    /// 对齐 refreshCaptchaToken()
    async fn refresh_captcha_token(&self, action: &str, metas: Value) -> Result<(), String> {
        let cur = self.captcha_token.lock().unwrap().clone();
        let body = json!({
            "action": action,
            "captcha_token": cur,
            "client_id": CLIENT_ID,
            "device_id": self.device_id,
            "meta": metas,
            "redirect_uri": "xlaccsdk01://xunlei.com/callback?state=harbor",
        });
        let resp = self
            .request(
                Method::POST,
                &format!("{XLUSER_API_URL}/shield/captcha/init"),
                None,
                Some(body),
                false,
                false,
            )
            .await?;
        if let Some(u) = resp
            .get("url")
            .and_then(|x| x.as_str())
            .filter(|s| !s.is_empty())
        {
            return Err(format!("迅雷需要人机验证，请在浏览器打开: {u}"));
        }
        let token = resp
            .get("captcha_token")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if token.is_empty() {
            return Err("迅雷 captcha_token 为空".into());
        }
        *self.captcha_token.lock().unwrap() = token.clone();
        self.save_credential("", &token);
        Ok(())
    }

    /// 对齐 RefreshCaptchaTokenAtLogin()
    async fn refresh_captcha_token_at_login(
        &self,
        action: &str,
        user_id: &str,
    ) -> Result<(), String> {
        let (timestamp, sign) = self.captcha_sign();
        let metas = json!({
            "client_version": CLIENT_VERSION,
            "package_name": PACKAGE_NAME,
            "user_id": user_id,
            "timestamp": timestamp,
            "captcha_sign": sign,
        });
        self.refresh_captcha_token(action, metas).await
    }

    /// 对齐 RefreshCaptchaTokenInLogin()
    async fn refresh_captcha_token_in_login(&self, action: &str) -> Result<(), String> {
        let metas = if self.username.contains('@') && self.username.contains('.') {
            json!({ "email": self.username })
        } else if (11..=18).contains(&self.username.len()) {
            json!({ "phone_number": self.username })
        } else {
            json!({ "username": self.username })
        };
        self.refresh_captcha_token(action, metas).await
    }

    /// 对齐 refreshTokenFunc：先刷新，失败则重新登录
    async fn do_refresh_token(&self) -> Result<(), String> {
        let cur = self
            .token
            .lock()
            .unwrap()
            .as_ref()
            .map(|t| t.refresh_token.clone())
            .or_else(|| Some(self.saved_refresh.clone()))
            .filter(|s| !s.is_empty());
        if let Some(refresh) = cur {
            match self._refresh_token(&refresh).await {
                Ok(t) => {
                    *self.token.lock().unwrap() = Some(t);
                    return Ok(());
                }
                Err(_) => return self.login().await,
            }
        }
        self.login().await
    }

    /// 对齐 RefreshToken()
    async fn _refresh_token(&self, refresh_token: &str) -> Result<TokenResp, String> {
        let body = json!({
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        });
        // request -> do_refresh_token -> _refresh_token -> request 构成 async 递归环，
        // 此处装箱断开（对齐 pan123 的 Box::pin 做法）
        let resp = Box::pin(self.request(
            Method::POST,
            &format!("{XLUSER_API_URL}/auth/token"),
            None,
            Some(body),
            false,
            false,
        ))
        .await?;
        if resp
            .get("refresh_token")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .is_empty()
        {
            return Err("迅雷刷新 token 返回空 refresh_token".into());
        }
        let t = token_from(&resp);
        self.save_credential(&t.refresh_token, "");
        Ok(t)
    }

    /// 对齐 CoreLogin()：v3 登录取 sessionID
    async fn core_login(&self) -> Result<String, String> {
        let body = json!({
            "protocolVersion": "301",
            "sequenceNo": "1000012",
            "platformVersion": "10",
            "isCompressed": "0",
            "appid": APPID,
            "clientVersion": CLIENT_VERSION,
            "peerID": "00000000000000000000000000000000",
            "appName": "ANDROID-com.xunlei.downloadprovider",
            "sdkVersion": "512000",
            "devicesign": generate_device_sign(&self.device_id, PACKAGE_NAME),
            "netWorkType": "WIFI",
            "providerName": "NONE",
            "deviceModel": "M2004J7AC",
            "deviceName": "Xiaomi_M2004j7ac",
            "OSVersion": "12",
            "creditkey": "",
            "hl": "zh-CN",
            "userName": self.username,
            "passWord": self.password,
            "verifyKey": "",
            "verifyCode": "",
            "isMd5Pwd": "0",
        });
        let resp = self
            .http
            .post(format!("{XLUSER_API_BASE_URL}/xluser.core.login/v3/login"))
            .header(
                "User-Agent",
                "android-ok-http-client/xl-acc-sdk/version-5.0.12.512000",
            )
            .header("accept", "application/json;charset=UTF-8")
            .header("x-device-id", &self.device_id)
            .header("x-client-id", CLIENT_ID)
            .header("x-client-version", CLIENT_VERSION)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("迅雷登录请求失败: {e}"))?;
        let v: Value = resp
            .json()
            .await
            .map_err(|e| format!("登录响应解析失败: {e}"))?;
        if let Some(err) = v
            .get("error")
            .and_then(|x| x.as_str())
            .filter(|s| !s.is_empty() && *s != "success")
        {
            let desc = v
                .get("error_description")
                .and_then(|x| x.as_str())
                .unwrap_or("");
            return Err(format!("迅雷登录失败: {err} {desc}"));
        }
        let session_id = v
            .get("sessionID")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if session_id.is_empty() {
            return Err("迅雷登录失败：未返回 sessionID".into());
        }
        Ok(session_id)
    }

    /// 对齐 Login()：core login -> captcha token -> signin/token
    async fn login(&self) -> Result<(), String> {
        let session_id = self.core_login().await?;
        let url = format!("{XLUSER_API_URL}/auth/signin/token");
        let action = get_action("POST", &url);
        self.refresh_captcha_token_in_login(&action).await?;
        let body = json!({
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "provider": SIGN_PROVIDER,
            "signin_token": session_id,
        });
        let resp = self
            .request(Method::POST, &url, None, Some(body), false, false)
            .await?;
        if resp
            .get("refresh_token")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .is_empty()
        {
            return Err("迅雷登录失败：未返回 refresh_token".into());
        }
        let t = token_from(&resp);
        *self.token.lock().unwrap() = Some(t.clone());
        self.save_credential(&t.refresh_token, "");
        Ok(())
    }

    /// 对齐 Init()/IsLogin()：登录并校验
    pub async fn validate(&self) -> Result<(), String> {
        if self.token.lock().unwrap().is_none() {
            if !self.saved_refresh.is_empty() {
                match self._refresh_token(&self.saved_refresh.clone()).await {
                    Ok(t) => {
                        *self.token.lock().unwrap() = Some(t);
                    }
                    Err(_) => self.login().await?,
                }
            } else {
                self.login().await?;
            }
        }
        self.request(
            Method::GET,
            &format!("{XLUSER_API_URL}/user/me"),
            None,
            None,
            true,
            false,
        )
        .await?;
        Ok(())
    }

    /// 对齐 getFiles()：page_token 分页
    pub async fn list(&self, parent_id: &str) -> Result<Vec<Entry>, String> {
        let mut files = Vec::new();
        let mut page_token = String::new();
        loop {
            let query = vec![
                ("space".into(), String::new()),
                ("__type".into(), "drive".into()),
                ("refresh".into(), "true".into()),
                ("__sync".into(), "true".into()),
                ("parent_id".into(), parent_id.to_string()),
                ("page_token".into(), page_token.clone()),
                ("with_audit".into(), "true".into()),
                ("limit".into(), "100".into()),
                (
                    "filters".into(),
                    r#"{"phase":{"eq":"PHASE_TYPE_COMPLETE"},"trashed":{"eq":false}}"#.into(),
                ),
            ];
            let resp = self
                .request(Method::GET, FILE_API_URL, Some(&query), None, true, false)
                .await?;
            let list = resp
                .get("files")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            for f in &list {
                let updated_at = f
                    .get("modified_time")
                    .and_then(|v| v.as_str())
                    .and_then(super::aliyundrive_open::iso_to_ms);
                files.push(Entry {
                    fid: f
                        .get("id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    name: f
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    size: f
                        .get("size")
                        .and_then(|v| v.as_str())
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0),
                    is_dir: f.get("kind").and_then(|v| v.as_str()) == Some("drive#folder"),
                    updated_at,
                    etag: None,
                    s3_key_flag: None,
                    file_type: None,
                    extra: None,
                });
            }
            page_token = resp
                .get("next_page_token")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if page_token.is_empty() {
                break;
            }
        }
        Ok(files)
    }

    /// 对齐 Link()：取 web_content_link，下载需 Dalvik UA
    pub async fn download(&self, e: &Entry) -> Result<DownloadInfo, String> {
        let url = format!("{FILE_API_URL}/{}", e.fid);
        let resp = self
            .request(
                Method::GET,
                &url,
                Some(&[("space".into(), String::new())]),
                None,
                true,
                false,
            )
            .await?;
        let link = resp
            .get("web_content_link")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if link.is_empty() {
            return Err("迅雷未返回下载直链".into());
        }
        Ok(DownloadInfo {
            url: link,
            headers: vec![("User-Agent".into(), DOWNLOAD_USER_AGENT.into())],
            proxy: true,
            local_path: None,
        })
    }

    // ================================================================
    // 写操作（对齐 Go 版 XunLeiCommon MakeDir/Rename/Move/Copy/Remove/Put）
    // ================================================================

    /// 对齐 MakeDir()：POST /drive/v1/files
    pub async fn mkdir(&self, parent_fid: &str, name: &str) -> Result<(), String> {
        let body = json!({
            "kind": FOLDER_KIND,
            "name": name,
            "parent_id": parent_fid,
            "space": "",
        });
        self.request(Method::POST, FILE_API_URL, None, Some(body), true, false)
            .await?;
        Ok(())
    }

    /// 对齐 Rename()：PATCH /drive/v1/files/{fileID}
    pub async fn rename(&self, parent_fid: &str, e: &Entry, new_name: &str) -> Result<(), String> {
        let _ = parent_fid;
        let url = format!("{FILE_API_URL}/{}", e.fid);
        let body = json!({
            "name": new_name,
            "space": "",
        });
        self.request(Method::PATCH, &url, None, Some(body), true, false)
            .await?;
        Ok(())
    }

    /// 对齐 Move()：POST /drive/v1/files:batchMove
    pub async fn move_entry(
        &self,
        parent_fid: &str,
        e: &Entry,
        dst_dir_fid: &str,
    ) -> Result<(), String> {
        let _ = parent_fid;
        let url = format!("{FILE_API_URL}:batchMove");
        let body = json!({
            "to": { "parent_id": dst_dir_fid },
            "ids": [e.fid],
            "space": "",
        });
        self.request(Method::POST, &url, None, Some(body), true, false)
            .await?;
        Ok(())
    }

    /// 对齐 Copy()：POST /drive/v1/files:batchCopy
    pub async fn copy(&self, parent_fid: &str, e: &Entry, dst_dir_fid: &str) -> Result<(), String> {
        let _ = parent_fid;
        let url = format!("{FILE_API_URL}:batchCopy");
        let body = json!({
            "to": { "parent_id": dst_dir_fid },
            "ids": [e.fid],
            "space": "",
        });
        self.request(Method::POST, &url, None, Some(body), true, false)
            .await?;
        Ok(())
    }

    /// 对齐 Remove()：PATCH /drive/v1/files/{fileID}/trash?space=
    pub async fn remove(&self, parent_fid: &str, e: &Entry) -> Result<(), String> {
        let _ = parent_fid;
        let url = format!("{FILE_API_URL}/{}/trash", e.fid);
        let query = vec![("space".into(), String::new())];
        self.request(
            Method::PATCH,
            &url,
            Some(&query),
            Some(json!({})),
            true,
            false,
        )
        .await?;
        Ok(())
    }

    /// 对齐 Put()：算 GCID（对齐 getGcid()：分块 sha1 的哈希串接后整体再 sha1）
    /// -> POST /drive/v1/files（upload_type=UPLOAD_TYPE_RESUMABLE）创建上传任务
    /// -> S3 分片直传（静态凭据，AWS SigV4 + UNSIGNED-PAYLOAD）。
    /// GCID 块长依赖文件总大小且分片重试需重读 -> reader 先落临时文件再计算/上传。
    pub async fn put(&self, dst_dir_fid: &str, input: super::PutInput) -> Result<(), String> {
        // 1. reader 只能读一次：落临时文件（guard 保证任何路径退出都删除）
        let tmp = temp_file_path();
        let _guard = TempFileGuard(tmp.clone());
        let actual_size = spool_to_file(input.reader, &tmp).await?;
        let size = if input.size != 0 {
            input.size
        } else {
            actual_size
        };
        // 2. GCID（对齐 getGcid()）
        let gcid = file_gcid(&tmp, size).await?;
        // 3. 创建上传任务
        let body = json!({
            "kind": FILE_KIND,
            "parent_id": dst_dir_fid,
            "name": input.name,
            "size": size,
            "hash": gcid,
            "upload_type": UPLOAD_TYPE_RESUMABLE,
            "space": "",
        });
        let resp = self
            .request(Method::POST, FILE_API_URL, None, Some(body), true, false)
            .await?;
        // 对齐 Go 版：仅处理 UPLOAD_TYPE_RESUMABLE，其它类型直接返回
        if resp.get("upload_type").and_then(|v| v.as_str()) != Some(UPLOAD_TYPE_RESUMABLE) {
            return Ok(());
        }
        let p = resp
            .pointer("/resumable/params")
            .cloned()
            .unwrap_or(Value::Null);
        let bucket = p
            .get("bucket")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let mut endpoint = p
            .get("endpoint")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let key = p
            .get("key")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let params = S3Params {
            access_key_id: p
                .get("access_key_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            access_key_secret: p
                .get("access_key_secret")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            security_token: p
                .get("security_token")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            expiration: p
                .get("expiration")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
        };
        if bucket.is_empty() || endpoint.is_empty() || key.is_empty() {
            return Err("迅雷上传响应缺少 S3 bucket/endpoint/key".into());
        }
        // 对齐 strings.TrimLeft(endpoint, bucket+".")：按字符集裁掉前缀
        let cutset = format!("{bucket}.");
        endpoint = endpoint
            .trim_start_matches(|c| cutset.contains(c))
            .to_string();
        let host = format!("{bucket}.{endpoint}");

        // 对齐 s3manager：超过 MaxUploadParts*DefaultPartSize 时调大分片
        let mut part_size = S3_DEFAULT_PART_SIZE;
        if size > S3_MAX_PARTS * S3_DEFAULT_PART_SIZE {
            part_size = size / (S3_MAX_PARTS - 1);
        }
        if size <= part_size {
            // 单请求直传（对齐 s3manager 单分片路径）
            let data = read_temp_part(&tmp, 0, size).await?;
            let (status, _, body) = self
                .s3_request(Method::PUT, &host, &key, "", &params, data)
                .await?;
            if !(200..300).contains(&status) {
                return Err(format!(
                    "迅雷 S3 上传失败：HTTP {status} {}",
                    truncate_for_log(&String::from_utf8_lossy(&body))
                ));
            }
            Ok(())
        } else {
            self.s3_multipart(&host, &key, &params, &tmp, size, part_size)
                .await
        }
    }

    /// AWS SigV4 签名的 S3 请求（对齐 aws-sdk-go：Region "xunlei"、service "s3"、
    /// 静态凭据 + UNSIGNED-PAYLOAD，签名头 host;x-amz-content-sha256;x-amz-date
    /// [;x-amz-security-token]）。返回 (HTTP 状态码, ETag, 响应体)
    async fn s3_request(
        &self,
        method: Method,
        host: &str,
        key: &str,
        canonical_query: &str,
        p: &S3Params,
        body: Vec<u8>,
    ) -> Result<(u16, Option<String>, Vec<u8>), String> {
        let (datestamp, amzdate) = utc_amz_dates();
        let region = S3_REGION;
        let service = "s3";
        // canonical headers（小写、按名字典序）
        let mut canonical_headers = format!("host:{host}\n");
        canonical_headers.push_str("x-amz-content-sha256:UNSIGNED-PAYLOAD\n");
        canonical_headers.push_str(&format!("x-amz-date:{amzdate}\n"));
        let mut signed_headers = "host;x-amz-content-sha256;x-amz-date".to_string();
        if !p.security_token.is_empty() {
            canonical_headers.push_str(&format!("x-amz-security-token:{}\n", p.security_token));
            signed_headers.push_str(";x-amz-security-token");
        }
        let canonical_uri = format!("/{}", s3_url_encode(key, false));
        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\nUNSIGNED-PAYLOAD",
            method.as_str(),
            canonical_uri,
            canonical_query,
            canonical_headers,
            signed_headers
        );
        let scope = format!("{datestamp}/{region}/{service}/aws4_request");
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amzdate}\n{scope}\n{}",
            hex(&sha256(canonical_request.as_bytes()))
        );
        // 签名密钥链：kSecret -> kDate -> kRegion -> kService -> kSigning
        let k = hmac_sha256(
            format!("AWS4{}", p.access_key_secret).as_bytes(),
            datestamp.as_bytes(),
        );
        let k = hmac_sha256(&k, region.as_bytes());
        let k = hmac_sha256(&k, service.as_bytes());
        let k = hmac_sha256(&k, b"aws4_request");
        let signature = hex(&hmac_sha256(&k, string_to_sign.as_bytes()));
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
            p.access_key_id, scope, signed_headers, signature
        );

        let url = if canonical_query.is_empty() {
            format!("https://{host}{canonical_uri}")
        } else {
            format!("https://{host}{canonical_uri}?{canonical_query}")
        };
        let mut req = self
            .http
            .request(method, &url)
            .header("x-amz-date", &amzdate)
            .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
            .header("Authorization", authorization);
        if !p.security_token.is_empty() {
            req = req.header("x-amz-security-token", &p.security_token);
        }
        if !p.expiration.is_empty() {
            // 对齐 UploadInput.Expires：透传 expiration
            req = req.header("Expires", &p.expiration);
        }
        let resp = req
            .body(body)
            .send()
            .await
            .map_err(|e| format!("迅雷 S3 上传请求失败: {e}"))?;
        let status = resp.status().as_u16();
        let etag = resp
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| format!("迅雷 S3 响应读取失败: {e}"))?;
        Ok((status, etag, bytes.to_vec()))
    }

    /// S3 分片上传（对齐 s3manager：init -> 逐片 PUT -> complete）
    async fn s3_multipart(
        &self,
        host: &str,
        key: &str,
        p: &S3Params,
        tmp: &std::path::Path,
        size: u64,
        part_size: u64,
    ) -> Result<(), String> {
        // 1. InitiateMultipartUpload（canonical query 空值参数也带 '='，与 SigV4 规范一致）
        let (status, _, body) = self
            .s3_request(Method::POST, host, key, "uploads=", p, Vec::new())
            .await?;
        if !(200..300).contains(&status) {
            return Err(format!(
                "迅雷 S3 初始化分片上传失败：HTTP {status} {}",
                truncate_for_log(&String::from_utf8_lossy(&body))
            ));
        }
        let upload_id = extract_xml_tag(&String::from_utf8_lossy(&body), "UploadId")?;

        // 2. 逐片 PUT（partNumber 从 1 开始）
        let mut parts: Vec<(u64, String)> = Vec::new();
        let mut offset = 0u64;
        let mut part_number = 1u64;
        while offset < size {
            let chunk = part_size.min(size - offset);
            let data = read_temp_part(tmp, offset, chunk).await?;
            let query = format!(
                "partNumber={part_number}&uploadId={}",
                s3_url_encode(&upload_id, true)
            );
            let (status, etag, body) = self
                .s3_request(Method::PUT, host, key, &query, p, data)
                .await?;
            if !(200..300).contains(&status) {
                return Err(format!(
                    "迅雷 S3 分片 {part_number} 上传失败：HTTP {status} {}",
                    truncate_for_log(&String::from_utf8_lossy(&body))
                ));
            }
            let etag = etag
                .map(|s| s.trim().trim_matches('"').to_string())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| format!("迅雷 S3 分片 {part_number} 响应缺少 ETag"))?;
            parts.push((part_number, etag));
            offset += chunk;
            part_number += 1;
        }

        // 3. CompleteMultipartUpload
        let mut xml = String::from("<CompleteMultipartUpload>");
        for (num, etag) in &parts {
            xml.push_str(&format!(
                "<Part><PartNumber>{num}</PartNumber><ETag>{etag}</ETag></Part>"
            ));
        }
        xml.push_str("</CompleteMultipartUpload>");
        let query = format!("uploadId={}", s3_url_encode(&upload_id, true));
        let (status, _, body) = self
            .s3_request(Method::POST, host, key, &query, p, xml.into_bytes())
            .await?;
        if !(200..300).contains(&status) {
            return Err(format!(
                "迅雷 S3 合并分片失败：HTTP {status} {}",
                truncate_for_log(&String::from_utf8_lossy(&body))
            ));
        }
        let body_str = String::from_utf8_lossy(&body);
        if body_str.contains("<Error") {
            return Err(format!(
                "迅雷 S3 合并分片失败: {}",
                truncate_for_log(&body_str)
            ));
        }
        Ok(())
    }
}

// ============================================================
// 写操作 / 上传辅助（对齐 pan115 的临时文件 + 手写密码学先例）
// ============================================================

/// S3 静态凭据（对齐 /resumable/params）
struct S3Params {
    access_key_id: String,
    access_key_secret: String,
    security_token: String,
    expiration: String,
}

/// 临时文件守卫：作用域结束（含错误路径）自动删除
struct TempFileGuard(std::path::PathBuf);

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn temp_file_path() -> PathBuf {
    std::env::temp_dir().join(format!("openlist-rs-thunder-{}", Uuid::new_v4()))
}

/// 把上传流落到临时文件，返回实际字节数
async fn spool_to_file(
    mut reader: std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send>>,
    path: &std::path::Path,
) -> Result<u64, String> {
    let mut f = tokio::fs::File::create(path)
        .await
        .map_err(|e| format!("迅雷创建临时文件失败: {e}"))?;
    let mut buf = vec![0u8; 256 * 1024];
    let mut total = 0u64;
    loop {
        let n = reader
            .read(&mut buf)
            .await
            .map_err(|e| format!("迅雷读取上传流失败: {e}"))?;
        if n == 0 {
            break;
        }
        f.write_all(&buf[..n])
            .await
            .map_err(|e| format!("迅雷写入临时文件失败: {e}"))?;
        total += n as u64;
    }
    f.flush()
        .await
        .map_err(|e| format!("迅雷临时文件落盘失败: {e}"))?;
    Ok(total)
}

/// 对齐 util.go getGcid()：按块（calcBlockSize(size)）sha1，块哈希串接后整体再 sha1。
/// 空文件对齐 Go 版：直接返回 sha1("")。
async fn file_gcid(path: &std::path::Path, size: u64) -> Result<String, String> {
    // calcBlockSize()
    let mut psize: u64 = 0x40000;
    while size / psize > 0x200 && psize < 0x200000 {
        psize <<= 1;
    }
    let mut f = tokio::fs::File::open(path)
        .await
        .map_err(|e| format!("迅雷打开临时文件失败: {e}"))?;
    let mut h1 = sha1::Sha1::new();
    let mut h2 = sha1::Sha1::new();
    let mut buf = vec![0u8; 256 * 1024];
    let mut block_left = psize;
    let mut block_has_data = false;
    loop {
        let want = block_left.min(buf.len() as u64) as usize;
        let n = f
            .read(&mut buf[..want])
            .await
            .map_err(|e| format!("迅雷读取临时文件失败: {e}"))?;
        if n == 0 {
            // 文件结束：冲刷最后不满一块的数据（空文件不冲刷，对齐 Go 版）
            if block_has_data {
                let sum = h2.finalize_reset();
                h1.update(sum);
            }
            break;
        }
        block_has_data = true;
        h2.update(&buf[..n]);
        block_left -= n as u64;
        if block_left == 0 {
            let sum = h2.finalize_reset();
            h1.update(sum);
            h2.reset();
            block_left = psize;
            block_has_data = false;
        }
    }
    Ok(hex(&h1.finalize()))
}

/// 从临时文件读取 [offset, offset+len) 分片
async fn read_temp_part(tmp: &std::path::Path, offset: u64, len: u64) -> Result<Vec<u8>, String> {
    let mut f = tokio::fs::File::open(tmp)
        .await
        .map_err(|e| format!("迅雷打开临时文件失败: {e}"))?;
    f.seek(std::io::SeekFrom::Start(offset))
        .await
        .map_err(|e| format!("迅雷临时文件 seek 失败: {e}"))?;
    let mut data = vec![0u8; len as usize];
    f.read_exact(&mut data)
        .await
        .map_err(|e| format!("迅雷读取临时分片失败: {e}"))?;
    Ok(data)
}

/// SHA-256（依赖列表无 sha2 crate，手写 FIPS 180-4；SigV4 签名用）
fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for (i, wi) in w.iter_mut().enumerate().take(16) {
            *wi = u32::from_be_bytes([
                chunk[4 * i],
                chunk[4 * i + 1],
                chunk[4 * i + 2],
                chunk[4 * i + 3],
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
        let (mut a, mut b, mut c, mut d, mut e, mut f2, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f2) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f2;
            f2 = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f2);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 32];
    for (i, v) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

/// HMAC-SHA256（RFC 2104，对齐 pan115/pan189 手写 hmac_sha1 的做法）
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = key.to_vec();
    if k.len() > BLOCK {
        k = sha256(&k).to_vec();
    }
    k.resize(BLOCK, 0);
    let mut inner = k.iter().map(|b| b ^ 0x36).collect::<Vec<_>>();
    inner.extend_from_slice(msg);
    let ih = sha256(&inner);
    let mut outer = k.iter().map(|b| b ^ 0x5c).collect::<Vec<_>>();
    outer.extend_from_slice(&ih);
    sha256(&outer)
}

// 日期换算统一走 drivers/timeutil（原为本地副本）
use super::timeutil::civil_from_days;

/// 当前 UTC 时间 -> (YYYYMMDD, YYYYMMDDTHHMMSSZ)（SigV4 x-amz-date 用）
fn utc_amz_dates() -> (String, String) {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let (hh, mi, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // civil_from_days（统一走 drivers/timeutil）
    let (y, m, d) = civil_from_days(days);
    let datestamp = format!("{y:04}{m:02}{d:02}");
    let amzdate = format!("{datestamp}T{hh:02}{mi:02}{ss:02}Z");
    (datestamp, amzdate)
}

/// SigV4 URI 编码：unreserved 字符（A-Za-z0-9-_.~）不编码；
/// encode_slash=false 时保留 '/'（S3 key path），true 时编码（query 值）
fn s3_url_encode(s: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b'/' if !encode_slash => out.push('/'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// 解析 S3 XML 响应中的单个标签
fn extract_xml_tag(xml: &str, tag: &str) -> Result<String, String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml
        .find(&open)
        .ok_or_else(|| format!("迅雷 S3 响应缺少 <{tag}>: {}", truncate_for_log(xml)))?
        + open.len();
    let end = xml[start..]
        .find(&close)
        .ok_or_else(|| format!("迅雷 S3 响应缺少 </{tag}>"))?
        + start;
    Ok(xml[start..end].to_string())
}

fn truncate_for_log(s: &str) -> String {
    if s.len() <= 200 {
        s.to_string()
    } else {
        // 回退到 UTF-8 字符边界，避免切片 panic
        let mut end = 200;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &s[..end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_action() {
        assert_eq!(
            get_action("POST", "https://xluser-ssl.xunlei.com/v1/auth/signin/token"),
            "POST:/v1/auth/signin/token"
        );
        assert_eq!(get_action("GET", "https://a.b/c/d?x=1"), "GET:/c/d");
    }

    #[test]
    fn test_device_sign_format() {
        let s = generate_device_sign("00000000000000000000000000000000", PACKAGE_NAME);
        assert!(s.starts_with("div101."));
    }

    #[test]
    fn test_sha256() {
        // FIPS 180-4 标准向量
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_hmac_sha256() {
        // RFC 4231 test case 2
        assert_eq!(
            hex(&hmac_sha256(
                b"key",
                b"The quick brown fox jumps over the lazy dog"
            )),
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
    }

    #[test]
    fn test_s3_url_encode() {
        assert_eq!(s3_url_encode("a/b c~_-.1", false), "a/b%20c~_-.1");
        assert_eq!(s3_url_encode("a/b", true), "a%2Fb");
    }
}
