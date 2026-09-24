//! 天翼云盘（189）驱动
//!
//! 移植自 OpenList Go 版 drivers/189（Cloud189）：
//! - 登录：账号密码经 RSA(PKCS1v15) 加密后走 open.e.189.cn 统一登录，
//!   依赖 cookie 会话（session 失效返回 InvalidSessionKey 时自动重登一次）
//! - 列表：/api/open/file/listFiles.action 分页拉取（默认根目录 -11）
//! - 直链：/api/portal/getFileInfo.action 取 downloadUrl 后跟一次 302 拿最终地址
//! - 写操作：mkdir/rename/move/copy/remove 走 open API，对齐 Go MakeDir/Rename/Move/Copy/Remove
//! - 上传：initMultiUpload（带整文件 MD5 + 分片聚合 MD5，支持秒传）
//!   -> getMultiUploadUrls 逐分片 PUT -> commitMultiUploadFile，对齐 Go newUpload()
//!   （Go 版提交后异步生成 .cas.torrent 的 CAS 附加特性未移植，不影响上传结果）

use super::DownloadInfo;
use crate::config::Entry;
use base64::Engine;
use md5::{Digest, Md5};
use rand::RngExt;
use reqwest::redirect::Policy;
use reqwest::{Client, Method};
use rsa::pkcs8::DecodePublicKey;
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};
use serde_json::{json, Value};
use sha1::Sha1;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

const LOGIN_URL: &str = "https://cloud.189.cn/api/portal/loginUrl.action?redirectURL=https%3A%2F%2Fcloud.189.cn%2Fmain.action";
const LOGIN_OK_URL: &str = "https://cloud.189.cn/web/main";
/// 对齐 Go 版 base.UserAgent（OpenList-4.2.6 drivers/base/client.go）
const UA: &str = "Mozilla/5.0 (Macintosh; Apple macOS 26_1_0) AppleWebKit/537.36 (KHTML, like Gecko) Safari/537.36 Chrome/142.0.0.0 OpenList/425.6.30";
/// API 请求的默认 Referer（对齐 Go 版 Init(): SetHeader("Referer", "https://cloud.189.cn/")）
const API_REFERER: &str = "https://cloud.189.cn/";

/// 天翼云盘 API 的默认根目录 id（对齐 Go 版 DefaultRoot: -11）
const DEFAULT_ROOT: &str = "-11";

pub struct Cloud189 {
    /// 带 cookie 会话的客户端（登录态保存在共享 cookie jar 中）
    http: Client,
    /// 不跟随重定向的客户端（与 http 共享 cookie jar，用于拿 302 直链）
    http_no_redirect: Client,
    username: String,
    password: String,
    /// 上传接口 RSA 公钥缓存 (pubKey, pkId, expire 毫秒)，对齐 Go d.rsa（getResKey 缓存）
    rsa_cache: Mutex<Option<(String, String, i64)>>,
}

/// 解析 "2024-01-02 15:04:05"（北京时间）-> epoch 毫秒（对齐 Go MustParseCNTime）
fn parse_cn_time(t: &str) -> Option<i64> {
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
    let days = days_from_civil(y, m as i64, d as i64);
    Some((days * 86_400 + hh as i64 * 3600 + mm as i64 * 60 + ss as i64 - 8 * 3600) * 1000)
}

/// 日期换算统一走 drivers/timeutil（原为本地副本）
use super::timeutil::days_from_civil;

/// 对齐 Go random()："0." + 17 位宽的随机数
fn random_param() -> String {
    let n: u64 = rand::rng().random_range(0..100_000_000_000_000_000);
    format!("0.{n:>17}")
}

/// 对齐 Go b64tohex：将 base64 字符串按特殊规则转换为 hex 字符串
/// 注意：不是「base64解码后hex编码」，而是 Go help.go 里的逐6bit映射算法
fn b64tohex(a: &str) -> String {
    const B64MAP: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const BI_RM: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let int2char = |i: usize| -> char { BI_RM[i] as char };
    let mut d = String::new();
    let mut e: u8 = 0;
    let mut c: usize = 0;
    for m in a.chars() {
        if m == '=' {
            continue;
        }
        let v = match B64MAP.iter().position(|&b| b == m as u8) {
            Some(pos) => pos,
            None => continue,
        };
        if e == 0 {
            e = 1;
            d.push(int2char(v >> 2));
            c = 3 & v;
        } else if e == 1 {
            e = 2;
            d.push(int2char((c << 2) | (v >> 4)));
            c = 15 & v;
        } else if e == 2 {
            e = 3;
            d.push(int2char(c));
            d.push(int2char(v >> 2));
            c = 3 & v;
        } else {
            e = 0;
            d.push(int2char((c << 2) | (v >> 4)));
            d.push(int2char(15 & v));
        }
    }
    if e == 1 {
        d.push(int2char(c << 2));
    }
    d
}

/// 对齐 Go RsaEncode(data, j_rsakey, hex=true)：
/// 1. 把 j_rsakey 包进 PEM 头尾解析 PKIX 公钥（Go: pem.Decode + x509.ParsePKIXPublicKey）
/// 2. RSA-PKCS1v15 加密
/// 3. base64 编码后走 b64tohex 转换（不是标准 hex::encode）
fn rsa_encrypt_hex(data: &[u8], j_rsakey: &str) -> Result<String, String> {
    let pem_str = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
        j_rsakey
    );
    let pub_key = RsaPublicKey::from_public_key_pem(&pem_str)
        .map_err(|e| format!("189 公钥解析失败: {e}"))?;
    let mut rng = rsa::rand_core::OsRng;
    let encrypted = pub_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, data)
        .map_err(|e| format!("189 RSA 加密失败: {e}"))?;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&encrypted);
    Ok(b64tohex(&b64))
}

/// 对齐 Go 版 utils.Json.Get(body, "result").ToInt()：
/// 天翼接口的 result 字段可能是字符串 "0" 也可能是整数 0，两者都视为成功
fn json_result(v: &Value) -> Option<i64> {
    match v.get("result")? {
        Value::Number(n) => n.as_i64(),
        Value::String(s) => s.trim().parse::<i64>().ok(),
        _ => None,
    }
}

impl Cloud189 {
    pub fn new(username: String, password: String) -> Self {
        // 共享 cookie jar：登录态在两个 client 之间通用（对齐 Go resty.NewWithClient(d.client)）
        // 注意：不要把 Referer 放进 default_headers——reqwest 的 RequestBuilder::header()
        // 是 append 语义（Go resty SetHeaders 是覆盖），会导致登录请求携带两个 Referer，
        // 天翼服务端返回 400 Bad Request。Referer 改为逐请求显式设置。
        let jar = Arc::new(reqwest::cookie::Jar::default());
        let http = Client::builder()
            .cookie_provider(jar.clone())
            .user_agent(UA)
            .build()
            .unwrap();
        let http_no_redirect = Client::builder()
            .cookie_provider(jar)
            .user_agent(UA)
            .redirect(Policy::none())
            .build()
            .unwrap();
        Cloud189 {
            http,
            http_no_redirect,
            username,
            password,
            rsa_cache: Mutex::new(None),
        }
    }

    /// 对齐 Go newLogin()：统一登录换 session cookie
    pub async fn login(&self) -> Result<(), String> {
        // Step 0: 访问 loginUrl，若最终跳到 web/main 说明已登录
        let res = self
            .http
            .get(LOGIN_URL)
            .send()
            .await
            .map_err(|e| format!("189 登录页请求失败: {e}"))?;
        let final_url = res.url().clone();
        if final_url.as_str() == LOGIN_OK_URL {
            return Ok(());
        }
        let q: Vec<(String, String)> = final_url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        let get = |key: &str| -> String {
            q.iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        let (lt, req_id, app_id) = (get("lt"), get("reqId"), get("appId"));
        if lt.is_empty() || app_id.is_empty() {
            return Err(format!("189 登录跳转参数缺失: {final_url}"));
        }
        let login_headers = |r: reqwest::RequestBuilder| -> reqwest::RequestBuilder {
            r.header("lt", &lt)
                .header("reqid", &req_id)
                .header("referer", final_url.as_str())
                .header("origin", "https://open.e.189.cn")
        };
        // 登录接口返回非 JSON 时带上 HTTP 状态与响应片段，便于定位问题（对齐 Go 版 Debug 日志）
        let expect_json = async |res: reqwest::Response, step: &str| -> Result<Value, String> {
            let status = res.status();
            let body = res
                .text()
                .await
                .map_err(|e| format!("189 {step} 读取响应失败: {e}"))?;
            serde_json::from_str::<Value>(&body).map_err(|_| {
                format!(
                    "189 {step} 响应非 JSON (HTTP {status}): {}",
                    super::truncate_bytes(&body, 200)
                )
            })
        };

        // Step 1: appConf
        let res = login_headers(
            self.http
                .post("https://open.e.189.cn/api/logbox/oauth2/appConf.do"),
        )
        .form(&[("version", "2.0"), ("appKey", app_id.as_str())])
        .send()
        .await
        .map_err(|e| format!("189 appConf 请求失败: {e}"))?;
        let conf: Value = expect_json(res, "appConf").await?;
        if json_result(&conf).unwrap_or(-1) != 0 {
            let msg = conf
                .get("msg")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown");
            return Err(format!("189 appConf 失败: {msg}"));
        }
        let account_type = conf
            .pointer("/data/accountType")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let return_url = conf
            .pointer("/data/returnUrl")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let mail_suffix = conf
            .pointer("/data/mailSuffix")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let param_id = conf
            .pointer("/data/paramId")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let client_type = conf
            .pointer("/data/clientType")
            .and_then(|v| v.as_i64())
            .unwrap_or(0)
            .to_string();
        let is_oauth2 = conf
            .pointer("/data/isOauth2")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
            .to_string();

        // Step 2: encryptConf（取 RSA 公钥与加密前缀）
        let res = login_headers(
            self.http
                .post("https://open.e.189.cn/api/logbox/config/encryptConf.do"),
        )
        .form(&[("appId", app_id.as_str())])
        .send()
        .await
        .map_err(|e| format!("189 encryptConf 请求失败: {e}"))?;
        let enc: Value = expect_json(res, "encryptConf").await?;
        if json_result(&enc).unwrap_or(-1) != 0 {
            return Err(format!("189 获取 encryptConf 失败: {enc}"));
        }
        let pre = enc
            .pointer("/data/pre")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let pub_key = enc
            .pointer("/data/pubKey")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        // Step 3: RSA 加密账号密码并提交登录
        // 用不跟随重定向的 client 发送，避免登录接口 302 时丢失 JSON 响应体（对齐 Go resty 拿到 body 后解析的行为）
        let user_rsa = rsa_encrypt_hex(self.username.as_bytes(), &pub_key)?;
        let pass_rsa = rsa_encrypt_hex(self.password.as_bytes(), &pub_key)?;
        let res = login_headers(
            self.http_no_redirect
                .post("https://open.e.189.cn/api/logbox/oauth2/loginSubmit.do"),
        )
        .form(&[
            ("version", "v2.0"),
            ("apToken", ""),
            ("appKey", app_id.as_str()),
            ("accountType", account_type.as_str()),
            ("userName", &format!("{pre}{user_rsa}")),
            ("epd", &format!("{pre}{pass_rsa}")),
            ("captchaType", ""),
            ("validateCode", ""),
            ("smsValidateCode", ""),
            ("captchaToken", ""),
            ("returnUrl", return_url.as_str()),
            ("mailSuffix", mail_suffix.as_str()),
            ("dynamicCheck", "FALSE"),
            ("clientType", client_type.as_str()),
            ("cb_SaveName", "3"),
            ("isOauth2", is_oauth2.as_str()),
            ("state", ""),
            ("paramId", param_id.as_str()),
        ])
        .send()
        .await
        .map_err(|e| format!("189 登录请求失败: {e}"))?;

        // 若登录接口直接返回重定向（对齐 Go resty 自动跟随 302 的行为），跟随回调换取 session
        if res.status().is_redirection() {
            let loc = res
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            if loc.is_empty() {
                return Err("189 登录返回重定向但缺少 Location".to_string());
            }
            self.follow_login_redirect(&loc).await?;
            return Ok(());
        }

        let login: Value = expect_json(res, "loginSubmit").await?;
        if json_result(&login).unwrap_or(-1) != 0 {
            let msg = login
                .get("msg")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown");
            return Err(format!("189 登录失败: {msg}"));
        }
        // 关键步骤：跟随登录响应里的 toUrl 完成 OAuth 回调跳转，
        // 换取 cloud.189.cn 的有效 session cookie（对齐 Go resty 自动跟随重定向链的行为）。
        // 没有这一步，后续 API 请求会因 session 无效而报 InvalidSessionKey/Bad Request。
        let to_url = login.get("toUrl").and_then(|v| v.as_str()).unwrap_or("");
        if to_url.is_empty() {
            return Err(format!("189 登录成功但未返回 toUrl: {login}"));
        }
        self.follow_login_redirect(to_url).await?;
        Ok(())
    }

    /// 跟随登录回调重定向链（callbackUnify.action → ... → cloud.189.cn），把 session cookie 写入 jar
    async fn follow_login_redirect(&self, start_url: &str) -> Result<(), String> {
        let mut current = reqwest::Url::parse(start_url)
            .map_err(|e| format!("189 登录回调地址无效 ({start_url}): {e}"))?;
        for _ in 0..10 {
            let res = self
                .http_no_redirect
                .get(current.clone())
                .send()
                .await
                .map_err(|e| format!("189 登录回调请求失败 ({current}): {e}"))?;
            if res.status().is_redirection() {
                let loc = res
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                if loc.is_empty() {
                    return Err(format!("189 登录回调重定向缺少 Location: {current}"));
                }
                current = current
                    .join(&loc)
                    .map_err(|e| format!("189 登录回调重定向地址无效 ({loc}): {e}"))?;
                continue;
            }
            return Ok(());
        }
        Err("189 登录回调重定向次数超限".to_string())
    }

    /// 对齐 Go request()：带 noCache 参数，InvalidSessionKey 自动重登一次，res_code 检查
    async fn request(
        &self,
        method: Method,
        url: &str,
        query: Option<&[(&str, &str)]>,
        retried: bool,
    ) -> Result<Value, String> {
        self.request_with_form(method, url, query, None, retried)
            .await
    }

    /// request() 的扩展版：支持 form 请求体（对齐 Go request 回调里 SetFormData 的场景），
    /// 会话刷新 / res_code 检查逻辑与 request() 完全一致
    async fn request_with_form(
        &self,
        method: Method,
        url: &str,
        query: Option<&[(&str, &str)]>,
        form: Option<&[(&str, &str)]>,
        retried: bool,
    ) -> Result<Value, String> {
        let mut req = self
            .http
            .request(method.clone(), url)
            .header("Accept", "application/json;charset=UTF-8")
            .header("Referer", API_REFERER)
            .query(&[("noCache", random_param())]);
        if let Some(q) = query {
            req = req.query(q);
        }
        if let Some(f) = form {
            req = req.form(f);
        }
        let resp = req.send().await.map_err(|e| format!("189 请求失败: {e}"))?;
        let v: Value = resp
            .json()
            .await
            .map_err(|e| format!("189 响应解析失败: {e}"))?;
        let error_code = v.get("errorCode").and_then(|e| e.as_str()).unwrap_or("");
        if error_code == "InvalidSessionKey" {
            if retried {
                return Err("189 会话失效且重登失败".into());
            }
            self.login().await?;
            return Box::pin(self.request_with_form(method, url, query, form, true)).await;
        }
        let res_code = v.get("res_code").and_then(|c| c.as_i64()).unwrap_or(0);
        if res_code != 0 {
            let msg = v
                .get("res_message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown");
            return Err(format!("189 接口错误(code={res_code}): {msg}"));
        }
        Ok(v)
    }

    /// 对齐 Go Init()：验证凭据（登录）
    pub async fn validate(&self) -> Result<(), String> {
        self.login().await?;
        Ok(())
    }

    fn normalize_fid(&self, fid: &str) -> String {
        if fid.is_empty() || fid == "0" {
            DEFAULT_ROOT.to_string()
        } else {
            fid.to_string()
        }
    }

    /// 对齐 Go getFiles()：listFiles.action 分页（60/页），count=0 停止
    pub async fn list(&self, parent_fid: &str) -> Result<Vec<Entry>, String> {
        let fid = self.normalize_fid(parent_fid);
        let mut files = Vec::new();
        let mut page: u32 = 1;
        loop {
            let page_str = page.to_string();
            let query = [
                ("pageSize", "60"),
                ("pageNum", page_str.as_str()),
                ("mediaType", "0"),
                ("folderId", fid.as_str()),
                ("iconOption", "5"),
                ("orderBy", "lastOpTime"),
                ("descending", "true"),
            ];
            let v = self
                .request(
                    Method::GET,
                    "https://cloud.189.cn/api/open/file/listFiles.action",
                    Some(&query),
                    false,
                )
                .await?;
            let ao = v.get("fileListAO").cloned().unwrap_or(Value::Null);
            let count = ao.get("count").and_then(|c| c.as_u64()).unwrap_or(0);
            if count == 0 {
                break;
            }
            if let Some(list) = ao.get("folderList").and_then(|l| l.as_array()) {
                for f in list {
                    files.push(Entry {
                        fid: f
                            .get("id")
                            .and_then(|i| i.as_i64())
                            .unwrap_or(0)
                            .to_string(),
                        name: f
                            .get("name")
                            .and_then(|n| n.as_str())
                            .unwrap_or("")
                            .to_string(),
                        size: 0,
                        is_dir: true,
                        updated_at: f
                            .get("lastOpTime")
                            .and_then(|t| t.as_str())
                            .and_then(parse_cn_time),
                        etag: None,
                        s3_key_flag: None,
                        file_type: None,
                        extra: None,
                    });
                }
            }
            if let Some(list) = ao.get("fileList").and_then(|l| l.as_array()) {
                for f in list {
                    files.push(Entry {
                        fid: f
                            .get("id")
                            .and_then(|i| i.as_i64())
                            .unwrap_or(0)
                            .to_string(),
                        name: f
                            .get("name")
                            .and_then(|n| n.as_str())
                            .unwrap_or("")
                            .to_string(),
                        size: f.get("size").and_then(|s| s.as_u64()).unwrap_or(0),
                        is_dir: false,
                        updated_at: f
                            .get("lastOpTime")
                            .and_then(|t| t.as_str())
                            .and_then(parse_cn_time),
                        etag: None,
                        s3_key_flag: None,
                        file_type: None,
                        extra: None,
                    });
                }
            }
            page += 1;
        }
        Ok(files)
    }

    /// 对齐 Go Link()：getFileInfo -> downloadUrl -> 跟一次 302 拿最终直链
    pub async fn download(&self, e: &Entry) -> Result<DownloadInfo, String> {
        let v = self
            .request(
                Method::GET,
                "https://cloud.189.cn/api/portal/getFileInfo.action",
                Some(&[("fileId", e.fid.as_str())]),
                false,
            )
            .await?;
        let first_url = v.get("downloadUrl").and_then(|u| u.as_str()).unwrap_or("");
        if first_url.is_empty() {
            return Err("189 未返回下载直链".into());
        }
        // Go 版 downloadUrl 字段缺协议头，补 "https:"
        let full = if first_url.starts_with("http") {
            first_url.to_string()
        } else {
            format!("https:{first_url}")
        };
        let mut final_url = full.clone();
        if let Ok(res) = self.http_no_redirect.get(&full).send().await {
            if res.status().as_u16() == 302 {
                if let Some(loc) = res.headers().get("location").and_then(|l| l.to_str().ok()) {
                    final_url = loc.to_string();
                }
            }
        }
        let final_url = final_url.replacen("http://", "https://", 1);
        Ok(DownloadInfo {
            url: final_url,
            headers: vec![],
            proxy: false,
            local_path: None,
        })
    }

    // ---------- 写操作（对齐 Go MakeDir/Rename/Move/Copy/Remove） ----------

    /// 对齐 Go MakeDir()：POST /api/open/file/createFolder.action
    pub async fn mkdir(&self, parent_fid: &str, name: &str) -> Result<(), String> {
        let pid = self.normalize_fid(parent_fid);
        self.request_with_form(
            Method::POST,
            "https://cloud.189.cn/api/open/file/createFolder.action",
            None,
            Some(&[("parentFolderId", pid.as_str()), ("folderName", name)]),
            false,
        )
        .await?;
        Ok(())
    }

    /// 对齐 Go Rename()：文件走 renameFile.action，文件夹走 renameFolder.action
    pub async fn rename(&self, parent_fid: &str, e: &Entry, new_name: &str) -> Result<(), String> {
        let _ = parent_fid;
        let (url, id_key, name_key) = if e.is_dir {
            (
                "https://cloud.189.cn/api/open/file/renameFolder.action",
                "folderId",
                "destFolderName",
            )
        } else {
            (
                "https://cloud.189.cn/api/open/file/renameFile.action",
                "fileId",
                "destFileName",
            )
        };
        self.request_with_form(
            Method::POST,
            url,
            None,
            Some(&[(id_key, e.fid.as_str()), (name_key, new_name)]),
            false,
        )
        .await?;
        Ok(())
    }

    /// 对齐 Go Move()/Copy()/Remove() 共用的 createBatchTask.action：
    /// taskInfos = [{"fileId","fileName","isFolder"}]，type 区分 MOVE/COPY/DELETE。
    /// 注意 Go Remove() 的 targetFolderId 是空串，这里不做 root 归一化。
    async fn batch_task(
        &self,
        task_type: &str,
        target_folder_id: &str,
        e: &Entry,
    ) -> Result<(), String> {
        let task_infos = serde_json::to_string(&json!({
            "fileId": e.fid,
            "fileName": e.name,
            "isFolder": if e.is_dir { 1 } else { 0 },
        }))
        .map_err(|err| format!("189 序列化 taskInfos 失败: {err}"))?;
        self.request_with_form(
            Method::POST,
            "https://cloud.189.cn/api/open/batch/createBatchTask.action",
            None,
            Some(&[
                ("type", task_type),
                ("targetFolderId", target_folder_id),
                ("taskInfos", task_infos.as_str()),
            ]),
            false,
        )
        .await?;
        Ok(())
    }

    /// 对齐 Go Move()：batch createBatchTask(type=MOVE)
    pub async fn move_entry(
        &self,
        parent_fid: &str,
        e: &Entry,
        dst_dir_fid: &str,
    ) -> Result<(), String> {
        let _ = parent_fid;
        let dst = self.normalize_fid(dst_dir_fid);
        self.batch_task("MOVE", dst.as_str(), e).await
    }

    /// 对齐 Go Copy()：batch createBatchTask(type=COPY)
    pub async fn copy(&self, parent_fid: &str, e: &Entry, dst_dir_fid: &str) -> Result<(), String> {
        let _ = parent_fid;
        let dst = self.normalize_fid(dst_dir_fid);
        self.batch_task("COPY", dst.as_str(), e).await
    }

    /// 对齐 Go Remove()：batch createBatchTask(type=DELETE, targetFolderId="")
    pub async fn remove(&self, parent_fid: &str, e: &Entry) -> Result<(), String> {
        let _ = parent_fid;
        self.batch_task("DELETE", "", e).await
    }

    // ---------- 上传（对齐 Go Put() -> newUpload()） ----------

    /// 对齐 Go getSessionKey()：getUserBriefInfo 拿上传接口用的 sessionKey
    async fn get_session_key(&self) -> Result<String, String> {
        let v = self
            .request(
                Method::GET,
                "https://cloud.189.cn/v2/getUserBriefInfo.action",
                None,
                false,
            )
            .await?;
        Ok(v.get("sessionKey")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string())
    }

    /// 对齐 Go getResKey()：上传接口的 RSA 公钥，带过期缓存
    async fn get_res_key(&self) -> Result<(String, String), String> {
        let now = now_ms();
        if let Some((pub_key, pk_id, expire)) = self.rsa_cache.lock().unwrap().as_ref() {
            if *expire > now {
                return Ok((pub_key.clone(), pk_id.clone()));
            }
        }
        let v = self
            .request(
                Method::GET,
                "https://cloud.189.cn/api/security/generateRsaKey.action",
                None,
                false,
            )
            .await?;
        let pub_key = v
            .get("pubKey")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let pk_id = v
            .get("pkId")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let expire = v.get("expire").and_then(|x| x.as_i64()).unwrap_or(0);
        *self.rsa_cache.lock().unwrap() = Some((pub_key.clone(), pk_id.clone(), expire));
        Ok((pub_key, pk_id))
    }

    /// 对齐 Go uploadRequest()：
    /// 1. 表单 k=v&k=v 原样拼接 -> AES-128/ECB(PKCS7) 加密 -> hex 作为 params 参数
    /// 2. HMAC-SHA1("SessionKey=..&Operate=GET&RequestURI=..&Date=..&params=..") 作为 Signature
    /// 3. 随机密钥 l（AES key = l[0:16]，签名/RSA 用整段 l）经 RSA 加密后放 EncryptionText 头
    /// 4. GET https://upload.cloud.189.cn{uri}?params={h}，code != "SUCCESS" 报错
    async fn upload_request(
        &self,
        session_key: &str,
        uri: &str,
        form: &[(String, String)],
    ) -> Result<Value, String> {
        let c = now_ms().to_string();
        let r = random_by_pattern("xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx");
        let mut l = random_by_pattern("xxxxxxxxxxxx4xxxyxxxxxxxxxxxxxxx");
        // 对齐 Go：l 截断为 16 + int(16*rand) 长度（16~31 字符）
        let cut = 16 + (rand::rng().random::<f32>() * 16.0) as usize;
        let cut = cut.min(l.len());
        l.truncate(cut);
        if l.len() < 16 {
            return Err("189 上传随机密钥生成异常".into());
        }

        let e = form_qs(form);
        let data = aes_encrypt_ecb(e.as_bytes(), &l.as_bytes()[..16])?;
        let h = hex::encode(&data);
        let signature = hmac_sha1_hex(
            format!("SessionKey={session_key}&Operate=GET&RequestURI={uri}&Date={c}&params={h}")
                .as_bytes(),
            l.as_bytes(),
        );
        let (pub_key, pk_id) = self.get_res_key().await?;
        let encryption_text = rsa_encrypt_b64(l.as_bytes(), &pub_key)?;

        let url = format!("https://upload.cloud.189.cn{uri}?params={h}");
        let resp = self
            .http
            .get(&url)
            .header("accept", "application/json;charset=UTF-8")
            .header("Referer", API_REFERER)
            .header("SessionKey", session_key)
            .header("Signature", signature)
            .header("X-Request-Date", &c)
            .header("X-Request-ID", r)
            .header("EncryptionText", encryption_text)
            .header("PkId", pk_id)
            .send()
            .await
            .map_err(|e| format!("189 上传接口请求失败: {e}"))?;
        let v: Value = resp
            .json()
            .await
            .map_err(|e| format!("189 上传接口响应解析失败: {e}"))?;
        if v.get("code").and_then(|x| x.as_str()).unwrap_or("") != "SUCCESS" {
            let msg = v
                .get("msg")
                .and_then(|m| m.as_str())
                .unwrap_or("")
                .to_string();
            return Err(format!("{uri}---{msg}"));
        }
        Ok(v)
    }

    /// 对齐 Go Put() -> newUpload()：
    /// 1. reader 落临时文件并顺带计算整文件 MD5 + 各 10MiB 分片 MD5（对齐 Go sliceHashWriter）
    /// 2. initMultiUpload（fileMd5/sliceMd5 命中秒传时 fileDataExists=1，直接 commit）
    /// 3. 非秒传：逐分片读临时文件 -> getMultiUploadUrls 取 CDN 地址 -> 带签名头 PUT
    /// 4. commitMultiUploadFile(lazyCheck=1, opertype=3)
    ///    Go 版提交后还会异步生成 .cas.torrent 并 oldUpload（CAS fork 特性），此处未移植。
    pub async fn put(&self, dst_dir_fid: &str, input: super::PutInput) -> Result<(), String> {
        const DEFAULT: u64 = 10485760;
        let dst = self.normalize_fid(dst_dir_fid);
        let tmp_path = temp_file_path();
        let _guard = TempFileGuard(tmp_path.clone());
        let (file_size, file_md5_hex, md5s) = spool_and_md5(input.reader, &tmp_path).await?;

        // 对齐 Go：多分片时 sliceMd5 = md5(join(各分片MD5, "\n"))，否则直接用整文件 MD5
        let slice_md5_hex = if file_size > DEFAULT && !md5s.is_empty() {
            let joined = md5s.join("\n");
            let mut h = Md5::new();
            h.update(joined.as_bytes());
            hex::encode(h.finalize())
        } else {
            file_md5_hex.clone()
        };

        let session_key = self.get_session_key().await?;

        // initMultiUpload（fileName 预 QueryEscape，对齐 Go encode()；fileSize 用实际落盘大小，
        // input.size==0 表示未知大小，落盘后即为真实值）
        let init_form = vec![
            ("parentFolderId".to_string(), dst),
            ("fileName".to_string(), query_escape(&input.name)),
            ("fileSize".to_string(), file_size.to_string()),
            ("sliceSize".to_string(), DEFAULT.to_string()),
            ("fileMd5".to_string(), file_md5_hex.clone()),
            ("sliceMd5".to_string(), slice_md5_hex.clone()),
        ];
        let res = self
            .upload_request(&session_key, "/person/initMultiUpload", &init_form)
            .await?;
        let upload_file_id = res
            .pointer("/data/uploadFileId")
            .map(|v| match v {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            })
            .unwrap_or_default();
        let file_data_exists = res
            .pointer("/data/fileDataExists")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);

        // 秒传命中：直接提交（对齐 Go fileDataExists == 1 分支）
        if file_data_exists == 1 {
            let form = commit_form(&upload_file_id, &file_md5_hex, &slice_md5_hex);
            self.upload_request(&session_key, "/person/commitMultiUploadFile", &form)
                .await?;
            return Ok(());
        }

        // 非秒传：逐分片从临时文件读取并上传（count = ceil(size / 10MiB)，空文件 count=0）
        let count = file_size.div_ceil(DEFAULT);
        let mut tf = tokio::fs::File::open(&tmp_path)
            .await
            .map_err(|e| format!("189 读取临时上传文件失败: {e}"))?;
        let uploader = Client::new();
        let mut finish: u64 = 0;
        let mut part: u64 = 1;
        while part <= count {
            let byte_size = std::cmp::min(file_size - finish, DEFAULT);
            let mut byte_data = vec![0u8; byte_size as usize];
            tf.read_exact(&mut byte_data)
                .await
                .map_err(|e| format!("189 读取第 {part} 分片失败: {e}"))?;
            finish += byte_size;

            // partInfo = "{partNumber}-{分片MD5的base64}"（对齐 Go）
            let mut h = Md5::new();
            h.update(&byte_data);
            let md5_b64 = base64::engine::general_purpose::STANDARD.encode(h.finalize());
            let part_info = format!("{part}-{md5_b64}");
            let form = vec![
                ("partInfo".to_string(), part_info),
                ("uploadFileId".to_string(), upload_file_id.clone()),
            ];
            let res = self
                .upload_request(&session_key, "/person/getMultiUploadUrls", &form)
                .await?;
            let part_key = format!("partNumber_{part}");
            let part_obj = res
                .get("uploadUrls")
                .and_then(|u| u.get(&part_key))
                .cloned()
                .unwrap_or(Value::Null);
            let request_url = part_obj
                .get("requestURL")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let request_header = part_obj
                .get("requestHeader")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if request_url.is_empty() {
                return Err(format!("189 第 {part} 分片未返回上传地址"));
            }

            // CDN PUT：请求头来自 percent-decode 后的 requestHeader（k=v&k=v 形式）
            // （对齐 Go：base.HttpClient 直传，不带会话 cookie）
            let headers_str = percent_decode(&request_header);
            let mut req = uploader.put(&request_url);
            for hv in headers_str.split('&') {
                if let Some(eq) = hv.find('=') {
                    req = req.header(&hv[..eq], &hv[eq + 1..]);
                }
            }
            let resp = req
                .body(byte_data)
                .send()
                .await
                .map_err(|e| format!("189 第 {part} 分片上传失败: {e}"))?;
            let _ = resp.bytes().await; // 对齐 Go：不校验 CDN 响应，仅消费 body
            part += 1;
        }

        let form = commit_form(&upload_file_id, &file_md5_hex, &slice_md5_hex);
        self.upload_request(&session_key, "/person/commitMultiUploadFile", &form)
            .await?;
        Ok(())
    }
}

// ---------- 写操作 / 上传辅助（文件级函数） ----------

/// 当前 Unix 毫秒
fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// 对齐 Go Random(pattern)：把 pattern 中每个 x/y 替换为随机 hex 位（y 恒为 8~b）
fn random_by_pattern(pattern: &str) -> String {
    let mut rng = rand::rng();
    pattern
        .chars()
        .map(|ch| {
            if ch == 'x' || ch == 'y' {
                let t = (rng.random::<f32>() * 16.0) as i64;
                let i = if ch == 'x' { t } else { 3 & t | 8 };
                format!("{i:x}")
            } else {
                ch.to_string()
            }
        })
        .collect()
}

/// 对齐 Go url.QueryEscape：保留 [A-Za-z0-9-_.~]，空格转 '+'，其余 %XX 大写
fn query_escape(s: &str) -> String {
    let mut out = String::new();
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

/// 对齐 Go url.PathUnescape：解 %XX（'+' 不转空格；Go 解失败整体返回空串，此处宽松处理）
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hi = (b[i + 1] as char).to_digit(16);
            let lo = (b[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// 对齐 Go qs() + EncodeParam()：k=v&k=v 原样拼接（值不转义，fileName 由调用方预编码）
fn form_qs(form: &[(String, String)]) -> String {
    form.iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// 对齐 Go hmacSha1()：HMAC-SHA1 -> hex（未引入 hmac crate，按 RFC 2104 手工组合）
fn hmac_sha1_hex(key: &[u8], data: &[u8]) -> String {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let mut h = Sha1::new();
        h.update(key);
        k[..20].copy_from_slice(&h.finalize());
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut h = Sha1::new();
    h.update(ipad);
    h.update(data);
    let inner = h.finalize();
    let mut h = Sha1::new();
    h.update(opad);
    h.update(inner);
    hex::encode(h.finalize())
}

/// 对齐 Go RsaEncode(data, j_rsakey, hex=false)：RSA-PKCS1v15 加密后 base64（不走 b64tohex）
fn rsa_encrypt_b64(data: &[u8], j_rsakey: &str) -> Result<String, String> {
    let pem_str = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
        j_rsakey
    );
    let pub_key = RsaPublicKey::from_public_key_pem(&pem_str)
        .map_err(|e| format!("189 上传公钥解析失败: {e}"))?;
    let encrypted = pub_key
        .encrypt(&mut rsa::rand_core::OsRng, Pkcs1v15Encrypt, data)
        .map_err(|e| format!("189 上传 RSA 加密失败: {e}"))?;
    Ok(base64::engine::general_purpose::STANDARD.encode(&encrypted))
}

/// 对齐 Go commitMultiUploadFile 表单
fn commit_form(upload_file_id: &str, file_md5: &str, slice_md5: &str) -> Vec<(String, String)> {
    vec![
        ("uploadFileId".to_string(), upload_file_id.to_string()),
        ("fileMd5".to_string(), file_md5.to_string()),
        ("sliceMd5".to_string(), slice_md5.to_string()),
        ("lazyCheck".to_string(), "1".to_string()),
        ("opertype".to_string(), "3".to_string()),
    ]
}

struct TempFileGuard(PathBuf);

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn temp_file_path() -> PathBuf {
    std::env::temp_dir().join(format!("openlist-rs-189-{}", Uuid::new_v4()))
}

/// 把只读一次的 reader 落到临时文件，同时计算：
/// - 整文件 MD5（小写 hex，对齐 Go fileMd5Hex）
/// - 各 10MiB 分片的 MD5（大写 hex，对齐 Go sliceHashWriter 按分片边界切分收集）
///   返回 (实际落盘字节数, 整文件 MD5, 分片 MD5 列表)
async fn spool_and_md5(
    mut reader: Pin<Box<dyn AsyncRead + Send>>,
    path: &Path,
) -> Result<(u64, String, Vec<String>), String> {
    const DEFAULT: u64 = 10485760;
    let mut file = tokio::fs::File::create(path)
        .await
        .map_err(|e| format!("189 创建临时上传文件失败: {e}"))?;
    let mut file_hash = Md5::new();
    let mut slice_hash = Md5::new();
    let mut md5s: Vec<String> = Vec::new();
    let mut finish: u64 = 0;
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = reader
            .read(&mut buf)
            .await
            .map_err(|e| format!("189 读取上传内容失败: {e}"))?;
        if n == 0 {
            break;
        }
        // 按 10MiB 分片边界切分哈希（对齐 Go sliceHashWriter.Write）
        let mut off = 0usize;
        while off < n {
            let slice_remain = (DEFAULT - finish % DEFAULT) as usize;
            let to_write = std::cmp::min(n - off, slice_remain);
            file_hash.update(&buf[off..off + to_write]);
            slice_hash.update(&buf[off..off + to_write]);
            off += to_write;
            finish += to_write as u64;
            if finish.is_multiple_of(DEFAULT) {
                let h = slice_hash.clone();
                md5s.push(hex::encode(h.finalize()).to_uppercase());
                slice_hash = Md5::new();
            }
        }
        file.write_all(&buf[..n])
            .await
            .map_err(|e| format!("189 写入临时上传文件失败: {e}"))?;
    }
    file.flush()
        .await
        .map_err(|e| format!("189 刷新临时上传文件失败: {e}"))?;
    // 最后一段不足 10MiB（或整个文件为空）也要记录分片 MD5（对齐 Go 收尾逻辑）
    if !finish.is_multiple_of(DEFAULT) || finish == 0 {
        let h = slice_hash.clone();
        md5s.push(hex::encode(h.finalize()).to_uppercase());
    }
    Ok((finish, hex::encode(file_hash.finalize()), md5s))
}

/// AES S-box（uploadRequest 需要 AES-128/ECB，Cargo.toml 无 aes crate 且不允许新增，内联实现）
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// GF(2^8) 上乘 2
fn xtime(x: u8) -> u8 {
    (x << 1) ^ if x & 0x80 != 0 { 0x1b } else { 0 }
}

/// AES-128 密钥扩展 -> 11 个轮密钥
fn aes128_expand_key(key: &[u8; 16]) -> [[u8; 16]; 11] {
    const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
    let mut w = [[0u8; 4]; 44];
    for i in 0..4 {
        w[i].copy_from_slice(&key[i * 4..i * 4 + 4]);
    }
    for i in 4..44 {
        let mut temp = w[i - 1];
        if i % 4 == 0 {
            // RotWord + SubWord
            temp = [
                SBOX[temp[1] as usize],
                SBOX[temp[2] as usize],
                SBOX[temp[3] as usize],
                SBOX[temp[0] as usize],
            ];
            temp[0] ^= RCON[i / 4 - 1];
        }
        for j in 0..4 {
            w[i][j] = w[i - 4][j] ^ temp[j];
        }
    }
    let mut round_keys = [[0u8; 16]; 11];
    for r in 0..11 {
        for c in 0..4 {
            round_keys[r][c * 4..c * 4 + 4].copy_from_slice(&w[r * 4 + c]);
        }
    }
    round_keys
}

/// AES-128 加密单个 16 字节块（state[r][c] = block[4c + r]）
fn aes128_encrypt_block(block: &mut [u8; 16], round_keys: &[[u8; 16]; 11]) {
    for i in 0..16 {
        block[i] ^= round_keys[0][i];
    }
    for round_key in &round_keys[1..10] {
        // SubBytes
        for b in block.iter_mut() {
            *b = SBOX[*b as usize];
        }
        // ShiftRows：行 r 循环左移 r
        let s = *block;
        for c in 0..4 {
            for r in 1..4 {
                block[4 * c + r] = s[4 * ((c + r) % 4) + r];
            }
        }
        // MixColumns
        for c in 0..4 {
            let a0 = block[4 * c];
            let a1 = block[4 * c + 1];
            let a2 = block[4 * c + 2];
            let a3 = block[4 * c + 3];
            block[4 * c] = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3;
            block[4 * c + 1] = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3;
            block[4 * c + 2] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3);
            block[4 * c + 3] = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3);
        }
        // AddRoundKey
        for i in 0..16 {
            block[i] ^= round_key[i];
        }
    }
    // 末轮：SubBytes + ShiftRows + AddRoundKey（无 MixColumns）
    for b in block.iter_mut() {
        *b = SBOX[*b as usize];
    }
    let s = *block;
    for c in 0..4 {
        for r in 1..4 {
            block[4 * c + r] = s[4 * ((c + r) % 4) + r];
        }
    }
    for i in 0..16 {
        block[i] ^= round_keys[10][i];
    }
}

/// 对齐 Go AesEncrypt()：PKCS7 填充 + AES-128 ECB（逐块独立加密，无 IV）
fn aes_encrypt_ecb(data: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != 16 {
        return Err("189 上传加密密钥长度非法".into());
    }
    let mut k = [0u8; 16];
    k.copy_from_slice(key);
    let round_keys = aes128_expand_key(&k);
    let pad = 16 - data.len() % 16;
    let mut padded = data.to_vec();
    padded.extend(std::iter::repeat_n(pad as u8, pad));
    for chunk in padded.chunks_mut(16) {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        aes128_encrypt_block(&mut block, &round_keys);
        chunk.copy_from_slice(&block);
    }
    Ok(padded)
}
