//! halalcloud 盘 OpenAPI 驱动（对齐 Go 版 drivers/halalcloud_open）
//!
//! 纯 HTTP 版本（不是 gRPC 的 `halalcloud` 驱动）：默认 host `openapi.2dland.cn`，
//! client_id/client_secret + access_token/refresh_token 鉴权。
//!
//! - 签名 `HL6-HMAC-SHA256`（SigV4 风格，见 Go SDK signer/signer.go）：
//!   canonical = METHOD\npath\nquery\ncanonicalHeaders\nsignedHeaders\nsha256hex(body)
//!   scope     = {YYYY-MM-DD}/{access_token}/hl6_request
//!   key       = HMAC(HMAC(HMAC("HL6"+secret, date), access_token), "hl6_request")
//! - 签名头固定含 host / x-hl-nonce(base36 UnixNano) / x-hl-timestamp(RFC3339)
//!   / `other-header: other-value`（SDK 里真有这个常量头，少一个就 401）；
//!   body 非空时额外签 content-type
//! - 401 → POST /v6/oauth/refresh_token 刷新后重试一次，刷新请求本身仍用旧 access_token 签名，
//!   新 access_token（会过期）与轮换后的 refresh_token 都写回账号凭据
//! - Entry.fid：文件为 identity，目录无 identity 时退化为 path；真实 path 存 entry.extra.path
//! - 下载走 get_direct_download_address 出直链（proxy = false，不需要服务端中转）
//! - 上传（create_upload_task + 分块 CID + 收尾）尚未实现，见文件末尾

use super::timeutil::civil_from_days;
use super::{truncate_bytes, DownloadInfo, PutInput};
use crate::config::{Credential, Entry, Store};
use hmac::{Hmac, Mac};
use reqwest::Client;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

const SIGN_ALG: &str = "HL6-HMAC-SHA256";
const SIGN_PREFIX: &str = "HL6";
const REQUEST_SUFFIX: &str = "hl6_request";
const DEFAULT_HOST: &str = "openapi.2dland.cn";
const DEFAULT_TIMEOUT: u64 = 60;
const OTHER_HEADER_KEY: &str = "other-header";
const OTHER_HEADER_VALUE: &str = "other-value";
const CONTENT_TYPE: &str = "application/json; charset=utf-8";
const LIST_LIMIT: i64 = 100;

pub struct HalalcloudOpen {
    account_id: String,
    store: Arc<Store>,
    http: Client,
    host: String,
    client_id: String,
    client_secret: String,
    access_token: Mutex<String>,
    refresh_token: Mutex<String>,
    root_path: String,
}

impl HalalcloudOpen {
    /// 显式列出全部字段：本仓多处驱动构造函数同样按参数平铺（见 yandex_disk/s3 等）
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: &str,
        client_id: String,
        client_secret: String,
        access_token: String,
        refresh_token: String,
        host: String,
        timeout: u64,
        root_path: String,
        store: Arc<Store>,
    ) -> Self {
        let host = {
            let h = host
                .trim()
                .trim_start_matches("https://")
                .trim_end_matches('/');
            if h.is_empty() {
                DEFAULT_HOST.to_string()
            } else {
                h.to_string()
            }
        };
        let root_path = {
            let p = root_path.trim();
            if p.is_empty() {
                "/".to_string()
            } else {
                format!("/{}", p.trim_matches('/'))
            }
        };
        let timeout = if timeout == 0 {
            DEFAULT_TIMEOUT
        } else {
            timeout
        };
        HalalcloudOpen {
            account_id: account_id.to_string(),
            store,
            http: Client::builder()
                .timeout(std::time::Duration::from_secs(timeout))
                .build()
                .unwrap_or_else(|_| Client::new()),
            host,
            client_id,
            client_secret,
            access_token: Mutex::new(access_token),
            refresh_token: Mutex::new(refresh_token),
            root_path,
        }
    }

    /// fid 解析：空 / "0" / "/" 都落到配置的 root_path
    fn resolve(&self, fid: &str) -> String {
        let f = fid.trim();
        if f.is_empty() || f == "0" || f == "/" {
            self.root_path.clone()
        } else {
            f.to_string()
        }
    }

    /// 取条目的 identity 与真实 path（path 存在 extra 里，见 list）
    fn id_and_path(&self, e: &Entry) -> (String, String) {
        let extra = e.extra.as_ref();
        let path = extra
            .and_then(|x| x.get("path"))
            .and_then(|p| p.as_str())
            .unwrap_or("")
            .to_string();
        let id = extra
            .and_then(|x| x.get("id"))
            .and_then(|i| i.as_str())
            .unwrap_or("")
            .to_string();
        if !path.is_empty() {
            return (id, path);
        }
        // 兼容层（compat.rs）可能只带 fid 进来：目录的 fid 就是 path，文件的 fid 是 identity
        if e.is_dir {
            (String::new(), e.fid.clone())
        } else {
            (e.fid.clone(), String::new())
        }
    }

    /// Rename / Move 的 source：Go 版只传 path（driver_curd_impl.go:66-73、50-64），
    /// path 缺失时退化为 identity（API 两种都收）
    fn path_or_id(&self, e: &Entry) -> Value {
        let (id, path) = self.id_and_path(e);
        if path.is_empty() {
            json!({ "identity": id })
        } else {
            json!({ "path": path })
        }
    }

    /// 组装签名头（时间戳/nonce 由调用方传入：单测可固定输入，便于与独立实现比对）
    ///
    /// 返回除 host 外的全部请求头（host 由 reqwest 按 URL 自动带上，值与签名里的 host 一致）
    #[allow(clippy::too_many_arguments)]
    fn signed_headers(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        access_token: &str,
        timestamp: &str,
        date: &str,
        nonce: &str,
    ) -> Vec<(String, String)> {
        let mut headers: Vec<(String, String)> = vec![
            ("host".into(), self.host.clone()),
            (OTHER_HEADER_KEY.into(), OTHER_HEADER_VALUE.into()),
            ("x-hl-nonce".into(), nonce.into()),
            ("x-hl-timestamp".into(), timestamp.into()),
        ];
        let mut names: Vec<String> = vec![
            "host".into(),
            OTHER_HEADER_KEY.into(),
            "x-hl-nonce".into(),
            "x-hl-timestamp".into(),
        ];
        if !body.is_empty() {
            headers.push(("content-type".into(), CONTENT_TYPE.into()));
            names.push("content-type".into());
        }
        names.sort();
        let canonical_headers: String = names
            .iter()
            .filter_map(|n| {
                headers
                    .iter()
                    .find(|(k, _)| k == n)
                    .map(|(k, v)| format!("{k}:{v}\n"))
            })
            .collect();
        let signed_headers = names.join(";");
        let payload_hash = hex::encode(Sha256::digest(body));
        // 本驱动所有请求都没有 query
        let canonical_request =
            format!("{method}\n{path}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}");
        let scope = format!("{date}/{access_token}/{REQUEST_SUFFIX}");
        let string_to_sign = format!(
            "{SIGN_ALG}\n{timestamp}\n{scope}\n{}",
            hex::encode(Sha256::digest(canonical_request.as_bytes()))
        );

        let mut mac = Hmac::<Sha256>::new_from_slice(
            format!("{SIGN_PREFIX}{}", self.client_secret).as_bytes(),
        )
        .expect("HMAC key");
        mac.update(date.as_bytes());
        let k_date = mac.finalize().into_bytes();
        let mut mac = Hmac::<Sha256>::new_from_slice(&k_date).expect("HMAC key");
        mac.update(access_token.as_bytes());
        let k_token = mac.finalize().into_bytes();
        let mut mac = Hmac::<Sha256>::new_from_slice(&k_token).expect("HMAC key");
        mac.update(REQUEST_SUFFIX.as_bytes());
        let signing_key = mac.finalize().into_bytes();
        let mut mac = Hmac::<Sha256>::new_from_slice(&signing_key).expect("HMAC key");
        mac.update(string_to_sign.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());

        let authorization = format!(
            "{SIGN_ALG} Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
            self.client_id
        );
        let mut out: Vec<(String, String)> =
            headers.into_iter().filter(|(k, _)| k != "host").collect();
        out.push(("authorization".into(), authorization));
        out
    }

    /// 带签名的单次请求；401 以 `unauthorized = true` 返回给上层决定是否刷新重试
    async fn send_once(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value, ApiErr> {
        let body_bytes = match body {
            Some(v) => serde_json::to_vec(v)
                .map_err(|e| ApiErr::new(format!("halalcloud 请求体序列化失败: {e}")))?,
            None => Vec::new(),
        };
        let token = self.access_token.lock().unwrap().clone();
        let (timestamp, date) = utc_now_rfc3339();
        let nonce = base36(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        );
        let url = format!("https://{}{path}", self.host);
        let mut req = self.http.request(method.clone(), &url);
        for (k, v) in self.signed_headers(
            method_str(&method),
            path,
            &body_bytes,
            &token,
            &timestamp,
            &date,
            &nonce,
        ) {
            req = req.header(k, v);
        }
        if !body_bytes.is_empty() {
            req = req.body(body_bytes);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| ApiErr::new(format!("halalcloud 请求失败: {e}")))?;
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        let v: Value = serde_json::from_str(&text).unwrap_or(json!({}));
        if status == 401 {
            return Err(ApiErr::unauthorized(format!(
                "halalcloud 未授权 (HTTP 401): {}",
                api_message(&v, &text)
            )));
        }
        if !(200..300).contains(&status) {
            return Err(ApiErr::new(format!(
                "halalcloud 接口错误 (HTTP {status}): {}",
                api_message(&v, &text)
            )));
        }
        Ok(v)
    }

    /// 统一请求：401 时刷新令牌并重试一次（对齐 SDK client.go:117-131）
    async fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value, String> {
        match self.send_once(method.clone(), path, body).await {
            Ok(v) => Ok(v),
            // 刷新端点自身不重试，避免递归
            Err(e) if e.unauthorized && !path.contains("/oauth") => {
                self.refresh_access_token().await?;
                self.send_once(method, path, body)
                    .await
                    .map_err(|e| e.message)
            }
            Err(e) => Err(e.message),
        }
    }

    /// 刷新 access_token（对齐 SDK client.go:205-234）并落盘
    async fn refresh_access_token(&self) -> Result<(), String> {
        let refresh_token = self.refresh_token.lock().unwrap().clone();
        if refresh_token.is_empty() {
            return Err(
                "halalcloud access_token 已失效且未配置 refresh_token，请重新填写凭据".into(),
            );
        }
        let body = json!({
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
            "client_id": self.client_id,
        });
        let v = self
            .send_once(
                reqwest::Method::POST,
                "/v6/oauth/refresh_token",
                Some(&body),
            )
            .await
            .map_err(|e| format!("halalcloud 刷新令牌失败: {}", e.message))?;
        let access_token = v
            .get("access_token")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if access_token.is_empty() {
            return Err("halalcloud 刷新令牌失败: 响应中没有 access_token".into());
        }
        // refresh_token 会轮换，返回空则沿用旧的
        let new_refresh = v
            .get("refresh_token")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let refresh_token = if new_refresh.is_empty() {
            refresh_token
        } else {
            new_refresh
        };
        *self.access_token.lock().unwrap() = access_token.clone();
        *self.refresh_token.lock().unwrap() = refresh_token.clone();
        self.store.update_credential(&self.account_id, |c| {
            if let Credential::HalalcloudOpen {
                access_token: at,
                refresh_token: rt,
                ..
            } = c
            {
                *at = access_token;
                *rt = refresh_token;
            }
        });
        Ok(())
    }

    pub async fn validate(&self) -> Result<(), String> {
        let v = self
            .request(reqwest::Method::POST, "/v6/user/get", Some(&json!({})))
            .await?;
        let identity = v.get("identity").map(value_to_string).unwrap_or_default();
        if identity.is_empty() {
            return Err("halalcloud 登录校验失败：响应中没有用户 identity".into());
        }
        Ok(())
    }

    pub async fn list(&self, parent_fid: &str) -> Result<Vec<Entry>, String> {
        let parent = self.resolve(parent_fid);
        let mut token = String::new();
        let mut out: Vec<Entry> = Vec::new();
        loop {
            let body = json!({
                "parent": { "path": parent },
                "list_info": { "limit": LIST_LIMIT, "token": token },
            });
            let v = self
                .request(reqwest::Method::POST, "/v6/userfile/list", Some(&body))
                .await?;
            if let Some(files) = v.get("files").and_then(|f| f.as_array()) {
                for f in files {
                    if let Some(e) = entry_from_json(f, &parent) {
                        out.push(e);
                    }
                }
            }
            // 分页 token 为空即结束（对齐 Go getFiles）
            token = v
                .pointer("/list_info/token")
                .map(value_to_string)
                .unwrap_or_default();
            if token.is_empty() {
                break;
            }
        }
        Ok(out)
    }

    pub async fn download(&self, e: &Entry) -> Result<DownloadInfo, String> {
        if e.is_dir {
            return Err("目录无法下载".into());
        }
        // Go 版 driver_get_link.go:24-27：identity 非空则 path 置空
        let (id, path) = self.id_and_path(e);
        let path = if id.is_empty() { path } else { String::new() };
        let v = self
            .request(
                reqwest::Method::POST,
                "/v6/userfile/get_direct_download_address",
                Some(&json!({ "identity": id, "path": path })),
            )
            .await?;
        let url = v
            .get("download_address")
            .map(value_to_string)
            .unwrap_or_default();
        if url.is_empty() {
            return Err("halalcloud 未返回下载直链".into());
        }
        Ok(DownloadInfo {
            url,
            headers: vec![],
            proxy: false,
            local_path: None,
        })
    }

    pub async fn mkdir(&self, parent_fid: &str, name: &str) -> Result<(), String> {
        let parent = self.resolve(parent_fid);
        // Go 版 makeDir 只传 Path + Name（不传 dir 标志）
        self.request(
            reqwest::Method::POST,
            "/v6/userfile/create",
            Some(&json!({ "path": parent, "name": name })),
        )
        .await?;
        Ok(())
    }

    pub async fn rename(&self, _parent_fid: &str, e: &Entry, new_name: &str) -> Result<(), String> {
        let mut body = self.path_or_id(e);
        body["name"] = json!(new_name);
        self.request(reqwest::Method::POST, "/v6/userfile/rename", Some(&body))
            .await?;
        Ok(())
    }

    pub async fn move_entry(
        &self,
        _parent_fid: &str,
        e: &Entry,
        dst_dir_fid: &str,
    ) -> Result<(), String> {
        // Go 版 move：source 只带 obj 自身 path，dest 只带目标目录 path
        let dest = self.resolve(dst_dir_fid);
        self.request(
            reqwest::Method::POST,
            "/v6/userfile/move",
            Some(&json!({
                "source": [self.path_or_id(e)],
                "dest": { "path": dest },
            })),
        )
        .await?;
        Ok(())
    }

    pub async fn copy(
        &self,
        _parent_fid: &str,
        e: &Entry,
        dst_dir_fid: &str,
    ) -> Result<(), String> {
        // 对齐 Go 版 halalcloud_open：有 identity 时 source 只带 identity，否则用 path；
        // 目标目录用 path（目录 fid 即 path）
        let (id, path) = self.id_and_path(e);
        let source_path = if id.is_empty() { path } else { String::new() };
        let dest = self.resolve(dst_dir_fid);
        self.request(
            reqwest::Method::POST,
            "/v6/userfile/copy",
            Some(&json!({
                "source": [{ "identity": id, "path": source_path }],
                "dest": { "path": dest },
            })),
        )
        .await?;
        Ok(())
    }

    pub async fn remove(&self, _parent_fid: &str, e: &Entry) -> Result<(), String> {
        let (id, path) = self.id_and_path(e);
        self.request(
            reqwest::Method::POST,
            "/v6/userfile/delete",
            Some(&json!({ "source": [{ "identity": id, "path": path }] })),
        )
        .await?;
        Ok(())
    }

    /// 上传：Go 版走 create_upload_task + 分块 CID(cid v1 raw+sha256) + 收尾 POST，
    /// 需要 base32 编码与 5 次 ×120s 重试，尚未移植
    pub async fn put(&self, _dst_dir_fid: &str, _input: PutInput) -> Result<(), String> {
        Err("halalcloud 上传尚未实现（只读 + 写操作已可用）".into())
    }
}

/// 接口错误（区分 401 以便触发刷新重试）
struct ApiErr {
    unauthorized: bool,
    message: String,
}

impl ApiErr {
    fn new(message: String) -> Self {
        ApiErr {
            unauthorized: false,
            message,
        }
    }

    fn unauthorized(message: String) -> Self {
        ApiErr {
            unauthorized: true,
            message,
        }
    }
}

/// 组装条目：fid 优先用 identity，目录无 identity 时用 path；path 原样存 extra
fn entry_from_json(f: &Value, parent: &str) -> Option<Entry> {
    let name = f.get("name").map(value_to_string).unwrap_or_default();
    if name.is_empty() {
        return None;
    }
    let is_dir = f.get("dir").and_then(|d| d.as_bool()).unwrap_or(false);
    let identity = f.get("identity").map(value_to_string).unwrap_or_default();
    let mut path = f.get("path").map(value_to_string).unwrap_or_default();
    if path.is_empty() {
        path = if parent.ends_with('/') {
            format!("{parent}{name}")
        } else {
            format!("{parent}/{name}")
        };
    }
    // 目录的 fid 必须是 path：open API 的 list 按 parent.path 查找（Go 版用 dir.GetPath()），
    // identity 在 extra 里随条目带走，写操作仍能用上；文件用 identity 便于取直链
    let fid = if is_dir || identity.is_empty() {
        path.clone()
    } else {
        identity.clone()
    };
    let update_ts = f.get("update_ts").map(value_to_i64).unwrap_or(0);
    Some(Entry {
        fid,
        name,
        size: f.get("size").map(value_to_i64).unwrap_or(0).max(0) as u64,
        is_dir,
        updated_at: if update_ts > 0 { Some(update_ts) } else { None },
        etag: None,
        s3_key_flag: None,
        file_type: None,
        extra: Some(json!({ "path": path, "id": identity })),
    })
}

/// 该 API 的数字字段既可能是数字也可能是字符串（protobuf json tag 带 `,string`）
fn value_to_i64(v: &Value) -> i64 {
    v.as_i64()
        .or_else(|| v.as_u64().map(|n| n as i64))
        .or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
        .unwrap_or(0)
}

fn value_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn method_str(m: &reqwest::Method) -> &str {
    m.as_str()
}

/// 当前 UTC 的 (RFC3339, YYYY-MM-DD)，对齐 Go 的 time.RFC3339 / "2006-01-02"
fn utc_now_rfc3339() -> (String, String) {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let (hh, mi, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    (
        format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mi:02}:{ss:02}Z"),
        format!("{y:04}-{m:02}-{d:02}"),
    )
}

/// Unix 纳秒转 base36（对齐 Go 的 strconv.FormatInt(nanos, 36)）
fn base36(mut n: u128) -> String {
    const ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    if n == 0 {
        return "0".to_string();
    }
    let mut buf = Vec::new();
    while n > 0 {
        buf.push(ALPHABET[(n % 36) as usize]);
        n /= 36;
    }
    buf.reverse();
    String::from_utf8(buf).unwrap_or_default()
}

/// 错误响应体：优先取 message 字段，否则截断原文
fn api_message(v: &Value, raw: &str) -> String {
    let msg = v.get("message").map(value_to_string).unwrap_or_default();
    if msg.is_empty() {
        truncate_bytes(raw, 200).to_string()
    } else {
        msg
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn driver() -> HalalcloudOpen {
        // Store 没有 Default：每个用例用独立临时目录（redb 同文件只允许一个实例持有锁）
        static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("ol-rs-halal-test-{}-{n}", std::process::id()));
        HalalcloudOpen {
            account_id: "acc".into(),
            store: Arc::new(Store::load(&dir.to_string_lossy())),
            http: Client::new(),
            host: DEFAULT_HOST.into(),
            client_id: "test-client".into(),
            client_secret: "test-secret".into(),
            access_token: Mutex::new("tok".into()),
            refresh_token: Mutex::new("rt".into()),
            root_path: "/".into(),
        }
    }

    #[test]
    fn test_base36() {
        assert_eq!(base36(0), "0");
        assert_eq!(base36(35), "z");
        assert_eq!(base36(36), "10");
        assert_eq!(base36(1295), "zz");
        assert_eq!(base36(46655), "zzz"); // 36^3-1
        assert_eq!(base36(1679615), "zzzz"); // 36^4-1
                                             // 真实量级：UnixNano
        assert_eq!(base36(1_700_000_000_000_000_000).len(), 12);
    }

    #[test]
    fn test_utc_now_rfc3339_format() {
        let (ts, date) = utc_now_rfc3339();
        assert_eq!(ts.len(), 20, "RFC3339 应为 YYYY-MM-DDTHH:MM:SSZ: {ts}");
        assert!(ts.ends_with('Z'));
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[10..11], "T");
        assert_eq!(&ts[13..14], ":");
        assert_eq!(date.len(), 10);
        assert_eq!(&ts[..10], date);
    }

    /// 签名交叉验证：期望值由 Python 按 Go SDK signer.go 独立复算（见提交说明）
    #[test]
    fn test_signature_matches_reference() {
        let d = driver();
        let body = br#"{"parent":{"path":"/"},"list_info":{"limit":100,"token":""}}"#;
        let headers = d.signed_headers(
            "POST",
            "/v6/userfile/list",
            body,
            "tok",
            "2026-09-24T04:05:06Z",
            "2026-09-24",
            "noncevalue",
        );
        let get = |k: &str| {
            headers
                .iter()
                .find(|(name, _)| name == k)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        assert_eq!(get("content-type"), CONTENT_TYPE);
        assert_eq!(get("other-header"), OTHER_HEADER_VALUE);
        assert_eq!(get("x-hl-nonce"), "noncevalue");
        assert_eq!(get("x-hl-timestamp"), "2026-09-24T04:05:06Z");
        assert!(
            !headers.iter().any(|(k, _)| k == "host"),
            "host 交给 reqwest 按 URL 生成"
        );
        assert_eq!(
            get("authorization"),
            "HL6-HMAC-SHA256 Credential=test-client/2026-09-24/tok/hl6_request, \
             SignedHeaders=content-type;host;other-header;x-hl-nonce;x-hl-timestamp, \
             Signature=27f72e49aafb7e9fcb381785ce4e6a459b7c1d3d6a6ebb9c7a26ebf7c6825720"
        );
    }

    /// 无 body 的请求不签 content-type
    #[test]
    fn test_signed_headers_without_body() {
        let d = driver();
        let headers = d.signed_headers(
            "POST",
            "/v6/user/get",
            b"",
            "tok",
            "2026-09-24T04:05:06Z",
            "2026-09-24",
            "noncevalue",
        );
        assert!(!headers.iter().any(|(k, _)| k == "content-type"));
        let auth = headers
            .iter()
            .find(|(k, _)| k == "authorization")
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        assert!(auth.contains("SignedHeaders=host;other-header;x-hl-nonce;x-hl-timestamp"));
        assert_eq!(
            auth,
            "HL6-HMAC-SHA256 Credential=test-client/2026-09-24/tok/hl6_request, \
             SignedHeaders=host;other-header;x-hl-nonce;x-hl-timestamp, \
             Signature=b10465a94e6c79c8bbd28b56a2acb39e826829e81397adef9d888c0096e3c745"
        );
    }

    #[test]
    fn test_resolve_and_id_and_path() {
        let d = driver();
        assert_eq!(d.resolve(""), "/");
        assert_eq!(d.resolve("0"), "/");
        assert_eq!(d.resolve("/"), "/");
        assert_eq!(d.resolve("/a/b"), "/a/b");

        let dir = Entry {
            fid: "/a".into(),
            name: "a".into(),
            size: 0,
            is_dir: true,
            updated_at: None,
            etag: None,
            s3_key_flag: None,
            file_type: None,
            extra: Some(json!({ "path": "/a", "id": "dir-id" })),
        };
        assert_eq!(d.id_and_path(&dir), ("dir-id".into(), "/a".into()));
        // Rename/Move 用 path；path 缺失才退化为 identity
        assert_eq!(d.path_or_id(&dir), json!({ "path": "/a" }));

        // 兼容层只给 fid 的两种情形
        let mut no_extra = dir.clone();
        no_extra.extra = None;
        assert_eq!(d.id_and_path(&no_extra), (String::new(), "/a".into()));
        let mut file = dir.clone();
        file.is_dir = false;
        file.extra = None;
        assert_eq!(d.id_and_path(&file), ("/a".into(), String::new()));
        assert_eq!(d.path_or_id(&file), json!({ "identity": "/a" }));
    }

    #[test]
    fn test_entry_from_json() {
        // size / update_ts 是字符串（protobuf json tag 带 `,string`）
        let f = json!({
            "identity": "file-id",
            "name": "a.mp4",
            "path": "/a.mp4",
            "dir": false,
            "size": "1234",
            "update_ts": "1700000000000",
        });
        let e = entry_from_json(&f, "/").unwrap();
        assert_eq!(e.fid, "file-id");
        assert_eq!(e.size, 1234);
        assert_eq!(e.updated_at, Some(1_700_000_000_000));
        assert!(!e.is_dir);
        assert_eq!(e.extra.as_ref().unwrap().get("path").unwrap(), "/a.mp4");

        // 数字形态也要吃得下
        let f = json!({ "name": "b", "dir": true, "size": 7, "update_ts": 5 });
        let e = entry_from_json(&f, "/x").unwrap();
        assert!(e.is_dir);
        assert_eq!(e.size, 7);
        assert_eq!(e.fid, "/x/b", "无 identity 的目录 fid 退化为 path");

        // 无 name 直接丢弃
        assert!(entry_from_json(&json!({ "identity": "x" }), "/").is_none());

        // 目录即使有 identity，fid 也必须是 path（list 按 parent.path 查找）
        let d = json!({ "identity": "dir-id", "name": "sub", "path": "/sub", "dir": true, "size": "0" });
        let e = entry_from_json(&d, "/").unwrap();
        assert_eq!(e.fid, "/sub");
        assert_eq!(e.extra.as_ref().unwrap().get("id").unwrap(), "dir-id");
    }
}
