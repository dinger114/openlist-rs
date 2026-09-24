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
//! - 上传：create_upload_task → 串行分块（CIDv1 raw+sha2-256，base32）→ 收尾 POST，
//!   块参数由服务端给、失败 5 次 ×120s 重试（对齐 Go halalcloud_upload.go）

use super::timeutil::civil_from_days;
use super::{truncate_bytes, DownloadInfo, PutInput};
use crate::config::{Credential, Entry, Store};
use hmac::{Hmac, KeyInit, Mac};
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

/// 上传分块默认值：服务端不在任务里给 block_size/block_codec/block_hash_type 时用这套
/// （0x55 = raw、0x12 = sha2-256，对齐 Go halalcloud_upload.go:39-47）
const DEFAULT_BLOCK_SIZE: usize = 4 * 1024 * 1024;
const DEFAULT_BLOCK_CODEC: u64 = 0x55;
const MH_SHA2_256: u64 = 0x12;

/// 上传重试：Go 版 common.go:11-12 —— 5 次、间隔 120s（阻塞 sleep，Rust 用 tokio 异步版）
const UPLOAD_RETRY_TIMES: usize = 5;
const UPLOAD_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(120);
/// 分块原始字节请求体上限保护：服务端给的分块不应超过这个量级（默认 4MB）
const UPLOAD_MAX_BLOCK_SIZE: u64 = 512 * 1024 * 1024;

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

    /// 上传：create_upload_task → 串行分块（每块算 CIDv1 后 POST 到任务给的 upload_address）→ 收尾
    ///
    /// 对齐 Go 版 halalcloud_upload.go：
    /// - 块大小/编解码器/哈希类型都由服务端在任务里给（block_size 等），缺省才用 4MiB / raw / sha2-256
    /// - 分块必须串行（Go 作者注：不确定 FileStream 是否支持并发读写）
    /// - `created=true`：服务端已有同内容文件（秒传），无需上传
    /// - 分块与收尾请求打到 upload_address（另一个域名），是明文请求，不带 HL6 签名头
    ///
    /// 与 Go 版的两处有意偏离：① 4xx 硬错误立即返回（Go 会 120s×5 白等 10 分钟）；
    /// ② 全程向 stderr 打诊断日志（服务端本来没有任何请求日志，上传出问题无从查）。
    pub async fn put(&self, dst_dir_fid: &str, mut input: PutInput) -> Result<(), String> {
        use tokio::io::AsyncReadExt;

        let name = input.name.clone();
        let size = input.size;
        // 目录的 fid 就是 path（见 entry_from_json）
        let new_path = join_remote_path(&self.resolve(dst_dir_fid), &name);
        let v = self
            .request(
                reqwest::Method::POST,
                "/v6/userfile/create_upload_task",
                Some(&json!({ "path": new_path, "size": size })),
            )
            .await?;
        let task = UploadTask::from_json(&v)?;
        eprintln!(
            "[halalcloud 上传] {new_path} ({size} 字节) 建任务: created={} task={} block_size={} codec={:#x} hash={:#x} upload_address={}",
            task.created, task.task, task.block_size, task.block_codec, task.block_hash_type, task.upload_address
        );
        if task.created {
            eprintln!("[halalcloud 上传] {new_path} 服务端已有同内容文件，秒传完成");
            return Ok(());
        }
        if task.task.is_empty() || task.upload_address.is_empty() {
            return Err("halalcloud 创建上传任务失败：响应里没有 task / upload_address".into());
        }
        if task.block_size > UPLOAD_MAX_BLOCK_SIZE {
            return Err(format!(
                "halalcloud 分块过大（{} 字节），拒绝分配缓冲",
                task.block_size
            ));
        }

        let block_size = task.block_size as usize;
        let mut buf = vec![0u8; block_size];
        let mut filled = 0usize;
        let mut slices: Vec<String> = Vec::new();
        loop {
            let n = input
                .reader
                .read(&mut buf[filled..])
                .await
                .map_err(|e| format!("halalcloud 读取上传流失败: {e}"))?;
            if n == 0 {
                break;
            }
            filled += n;
            if filled == block_size {
                slices.push(self.post_file_slice(&task, slices.len(), &buf).await?);
                filled = 0;
            }
        }
        // 尾块（大小不足 block_size 时也要单独算一个 CID）
        if filled > 0 {
            slices.push(
                self.post_file_slice(&task, slices.len(), &buf[..filled])
                    .await?,
            );
        }

        let created = self.make_file(&task, &slices).await?;
        eprintln!(
            "[halalcloud 上传] {new_path} 完成: {} 个分块, identity={}",
            slices.len(),
            created
                .get("identity")
                .map(value_to_string)
                .unwrap_or_default()
        );
        Ok(())
    }

    /// 上传单个分块：先 GET 探测（服务端返回 JSON bool，true = 该分块已存在可跳过），
    /// 否则 POST 原始字节；返回该分块的 CID（收尾要用同一个字符串）
    async fn post_file_slice(
        &self,
        task: &UploadTask,
        index: usize,
        data: &[u8],
    ) -> Result<String, String> {
        let cid = cid_v1(task.block_codec, task.block_hash_type, data)?;
        let url = format!(
            "{}/{}/{}",
            task.upload_address.trim_end_matches('/'),
            task.task,
            cid
        );
        let mut last_error = String::new();
        for attempt in 0..UPLOAD_RETRY_TIMES {
            match self.try_post_file_slice(&url, data).await {
                Ok(()) => {
                    eprintln!(
                        "[halalcloud 上传] 分块 #{index} 成功: {} 字节 cid={cid}",
                        data.len()
                    );
                    return Ok(cid);
                }
                Err(e) => {
                    eprintln!(
                        "[halalcloud 上传] 分块 #{index} 第 {} 次失败 (可重试={}): {}",
                        attempt + 1,
                        e.retryable,
                        e.message
                    );
                    if !e.retryable {
                        return Err(format!("halalcloud 上传分块失败（不重试）: {}", e.message));
                    }
                    last_error = e.message;
                }
            }
            if attempt + 1 < UPLOAD_RETRY_TIMES {
                tokio::time::sleep(UPLOAD_RETRY_INTERVAL).await;
            }
        }
        Err(format!(
            "halalcloud 上传分块失败（已重试 {UPLOAD_RETRY_TIMES} 次）: {last_error}"
        ))
    }

    async fn try_post_file_slice(&self, url: &str, data: &[u8]) -> Result<(), SliceErr> {
        let resp = self
            .http
            .get(url)
            .header("accept", "application/json")
            .send()
            .await
            .map_err(|e| SliceErr::soft(format!("halalcloud 探测分块失败: {e}")))?;
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        if status != 200 {
            return Err(SliceErr::of(
                status,
                format!(
                    "halalcloud 探测分块失败 (HTTP {status}): {}",
                    truncate_bytes(&text, 300)
                ),
            ));
        }
        // 已存在同 CID 的分块就不用再传了
        if serde_json::from_str::<bool>(text.trim()).unwrap_or(false) {
            return Ok(());
        }

        let resp = self
            .http
            .post(url)
            .header("accept", "application/json")
            .header("content-type", "application/octet-stream")
            .body(data.to_vec())
            .send()
            .await
            .map_err(|e| SliceErr::soft(format!("halalcloud 上传分块失败: {e}")))?;
        let status = resp.status().as_u16();
        if status != 200 && status != 201 {
            let text = resp.text().await.unwrap_or_default();
            return Err(SliceErr::of(
                status,
                format!(
                    "halalcloud 上传分块失败 (HTTP {status}): {}",
                    truncate_bytes(&text, 300)
                ),
            ));
        }
        Ok(())
    }

    /// 收尾：POST 分块 CID 清单，让服务端按顺序拼成一个文件
    async fn make_file(&self, task: &UploadTask, slices: &[String]) -> Result<Value, String> {
        let url = format!(
            "{}/{}",
            task.upload_address.trim_end_matches('/'),
            task.task
        );
        let mut last_error = String::new();
        for attempt in 0..UPLOAD_RETRY_TIMES {
            match self.try_make_file(&url, slices).await {
                Ok(v) => return Ok(v),
                Err(e) => {
                    eprintln!(
                        "[halalcloud 上传] 收尾第 {} 次失败 (可重试={}): {}",
                        attempt + 1,
                        e.retryable,
                        e.message
                    );
                    // 任务不存在/已过期、请求本身有问题时重试没有意义
                    if !e.retryable || e.message.contains("not found") {
                        return Err(e.message);
                    }
                    last_error = e.message;
                }
            }
            if attempt + 1 < UPLOAD_RETRY_TIMES {
                tokio::time::sleep(UPLOAD_RETRY_INTERVAL).await;
            }
        }
        Err(format!(
            "halalcloud 上传收尾失败（已重试 {UPLOAD_RETRY_TIMES} 次）: {last_error}"
        ))
    }

    async fn try_make_file(&self, url: &str, slices: &[String]) -> Result<Value, SliceErr> {
        let body = serde_json::to_vec(slices)
            .map_err(|e| SliceErr::hard(format!("halalcloud 分块清单序列化失败: {e}")))?;
        let resp = self
            .http
            .post(url)
            .header("accept", "application/json")
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| SliceErr::soft(format!("halalcloud 上传收尾失败: {e}")))?;
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        if status != 200 && status != 201 {
            return Err(SliceErr::of(
                status,
                format!(
                    "halalcloud 上传收尾失败 (HTTP {status}): {}",
                    truncate_bytes(&text, 300)
                ),
            ));
        }
        Ok(serde_json::from_str(&text).unwrap_or(Value::Null))
    }
}

/// 接口错误（区分 401 以便触发刷新重试）
struct ApiErr {
    unauthorized: bool,
    message: String,
}

/// 分块/收尾请求的错误：区分「重试可能有救」和「请求本身有问题，重试纯属白等」
struct SliceErr {
    retryable: bool,
    message: String,
}

impl SliceErr {
    fn hard(message: String) -> Self {
        SliceErr {
            retryable: false,
            message,
        }
    }

    fn soft(message: String) -> Self {
        SliceErr {
            retryable: true,
            message,
        }
    }

    /// 按 HTTP 状态码定性：4xx（除 408/429）是请求本身的问题
    fn of(status: u16, message: String) -> Self {
        if retryable_status(status) {
            SliceErr::soft(message)
        } else {
            SliceErr::hard(message)
        }
    }
}

/// 408 请求超时 / 429 限流 / 5xx / 网络错误 → 值得重试；其它 4xx 不值得
fn retryable_status(status: u16) -> bool {
    !(400..500).contains(&status) || status == 408 || status == 429
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

/// 上传任务（POST /v6/userfile/create_upload_task 的响应，字段名对齐 Go SDK UploadTask）
#[derive(Debug)]
struct UploadTask {
    /// true = 服务端已有同内容文件（秒传），无需上传
    created: bool,
    task: String,
    upload_address: String,
    block_size: u64,
    block_codec: u64,
    block_hash_type: u64,
}

impl UploadTask {
    fn from_json(v: &Value) -> Result<Self, String> {
        let get = |k: &str| v.get(k).map(value_to_string).unwrap_or_default();
        if v.get("created").and_then(|c| c.as_bool()).unwrap_or(false) {
            // 秒传：此时任务字段可以为空，直接返回
            return Ok(UploadTask {
                created: true,
                task: get("task"),
                upload_address: get("upload_address"),
                block_size: 0,
                block_codec: DEFAULT_BLOCK_CODEC,
                block_hash_type: MH_SHA2_256,
            });
        }
        let task = get("task");
        let upload_address = get("upload_address");
        if task.is_empty() || upload_address.is_empty() {
            return Err(format!(
                "halalcloud 创建上传任务失败: {}",
                api_message(v, "")
            ));
        }
        // 服务端给的区块参数是字符串（protobuf json tag 带 `,string`）；0 表示用默认值
        let block_size = v.get("block_size").map(value_to_i64).unwrap_or(0).max(0) as u64;
        let codec = v.get("block_codec").map(value_to_i64).unwrap_or(0).max(0) as u64;
        let hash_type = v
            .get("block_hash_type")
            .map(value_to_i64)
            .unwrap_or(0)
            .max(0) as u64;
        Ok(UploadTask {
            created: false,
            task,
            upload_address,
            block_size: if block_size > 0 {
                block_size
            } else {
                DEFAULT_BLOCK_SIZE as u64
            },
            block_codec: if codec > 0 {
                codec
            } else {
                DEFAULT_BLOCK_CODEC
            },
            block_hash_type: if hash_type > 0 {
                hash_type
            } else {
                MH_SHA2_256
            },
        })
    }
}

/// 分块 CID：CIDv1 = `[version=1][codec varint][mh_type varint][mh_len varint][digest]`，
/// 再按 multibase base32（小写、去填充，前缀 `b`）编码。
///
/// 等价于 Go 的 `cid.Prefix{Version: 1, Codec, MhType, MhLength: -1}.Sum(data)`：
/// codec 0x55 = raw、mh 0x12 = sha2-256（本驱动只用到 sha2-256，其它哈希类型直接报错）
fn cid_v1(codec: u64, hash_type: u64, data: &[u8]) -> Result<String, String> {
    if hash_type != MH_SHA2_256 {
        return Err(format!(
            "halalcloud 不支持的块哈希类型 {hash_type:#x}（目前只支持 sha2-256）"
        ));
    }
    let digest = Sha256::digest(data);
    let mut bytes = Vec::with_capacity(4 + digest.len());
    bytes.push(1); // CID version 1
    write_varint(&mut bytes, codec);
    write_varint(&mut bytes, hash_type);
    write_varint(&mut bytes, digest.len() as u64);
    bytes.extend_from_slice(&digest);
    Ok(format!("b{}", base32_lower_nopad(&bytes)))
}

/// 无符号 LEB128（go-varint / multiformats 同款）
fn write_varint(out: &mut Vec<u8>, mut n: u64) {
    while n >= 0x80 {
        out.push((n as u8 & 0x7f) | 0x80);
        n >>= 7;
    }
    out.push(n as u8);
}

/// RFC4648 base32（字母表 base32hex 之外的小写版本），去掉 `=` 填充：multibase 前缀 `b`
fn base32_lower_nopad(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in data {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 0x1f) as usize] as char);
        }
        // 丢掉已输出的高位，保证 acc 不会无限增长
        acc &= (1u32 << bits) - 1;
    }
    if bits > 0 {
        out.push(ALPHABET[((acc << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

/// 远端路径拼接：目录 fid 就是 path（根为 "/"）
fn join_remote_path(dir: &str, name: &str) -> String {
    format!("{}/{name}", dir.trim_end_matches('/'))
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

    // ----- 上传（CID / base32 / varint / 任务解析）-----

    /// 与 Rust 单测共用的确定性输入
    fn pattern(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn test_base32_lower_nopad() {
        // RFC4648 §10 测试向量（去掉 `=` 填充）
        assert_eq!(base32_lower_nopad(b""), "");
        assert_eq!(base32_lower_nopad(b"f"), "my");
        assert_eq!(base32_lower_nopad(b"fo"), "mzxq");
        assert_eq!(base32_lower_nopad(b"foo"), "mzxw6");
        assert_eq!(base32_lower_nopad(b"foob"), "mzxw6yq");
        assert_eq!(base32_lower_nopad(b"fooba"), "mzxw6ytb");
        assert_eq!(base32_lower_nopad(b"foobar"), "mzxw6ytboi");
        // 32 字节输入：51 个字符（32*8/5 上取整），且都是小写字母表内字符
        let s = base32_lower_nopad(&pattern(32));
        assert_eq!(s.len(), 52);
        assert!(s
            .chars()
            .all(|c| c.is_ascii_lowercase() || ('2'..='7').contains(&c)));
    }

    #[test]
    fn test_write_varint() {
        let mut out = Vec::new();
        write_varint(&mut out, 0);
        assert_eq!(out, vec![0x00]);
        out.clear();
        write_varint(&mut out, 0x7f);
        assert_eq!(out, vec![0x7f]);
        out.clear();
        write_varint(&mut out, 0x80);
        assert_eq!(out, vec![0x80, 0x01]);
        out.clear();
        write_varint(&mut out, 0x55); // raw
        assert_eq!(out, vec![0x55]);
        out.clear();
        write_varint(&mut out, 0x70); // dag-pb
        assert_eq!(out, vec![0x70]);
        out.clear();
        write_varint(&mut out, 300);
        assert_eq!(out, vec![0xac, 0x02]);
    }

    /// 期望值由 Go 版 go-cid 现算（`cid.Prefix{Version:1, Codec:0x55, MhType:0x12, MhLength:-1}.Sum()`）
    #[test]
    fn test_cid_v1_matches_go_cid() {
        let cases: Vec<(Vec<u8>, &str)> = vec![
            (
                vec![],
                "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku",
            ),
            (
                b"hello world".to_vec(),
                "bafkreifzjut3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e",
            ),
            (
                b"halalcloud".to_vec(),
                "bafkreidcuy4txwj2bgujkov2qpbnhi3oa7m43xxodbsqnsbedcn663eo4i",
            ),
            (
                pattern(32),
                "bafkreiddbxgsszwegntjcesujc53ew2p6qjkjhdtfwzmrk6bxbmbxvyq3u",
            ),
            (
                pattern(100),
                "bafkreif44cx7dhhvvjvhi2ndbvq5atsdo3slx5rycbjo5ht7gojfzfknki",
            ),
            (
                pattern(1 << 20),
                "bafkreidddocae7lltzjlkooe5a3tmiwsgazn7logjvqk7bzttsidpzhxne",
            ),
            (
                pattern(4 << 20), // 4MiB（默认块大小）
                "bafkreifbc4qqsqnawag4wlmfo7tibwcln6qov53a2kx4mvgjko4ylhku7i",
            ),
            (
                vec![0x41; 4 << 20],
                "bafkreiffq6e6sehf7e427rbtuah66wjqoauspxazfszdp7m6ore32376du",
            ),
        ];
        for (data, want) in cases {
            let got = cid_v1(DEFAULT_BLOCK_CODEC, MH_SHA2_256, &data).unwrap();
            assert_eq!(got, want, "长度 {} 的块 CID 不一致", data.len());
        }
        // codec 0x70（dag-pb）：只有编解码器那一个 varint 不同
        assert_eq!(
            cid_v1(0x70, MH_SHA2_256, &pattern(32)).unwrap(),
            "bafybeiddbxgsszwegntjcesujc53ew2p6qjkjhdtfwzmrk6bxbmbxvyq3u"
        );
    }

    /// 把 base32 解回来，逐个字节核对 multihash 结构（顺带验证编码器可逆）
    #[test]
    fn test_cid_bytes_layout() {
        const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
        fn decode(s: &str) -> Vec<u8> {
            let mut out = Vec::new();
            let (mut acc, mut bits) = (0u32, 0u32);
            for c in s.bytes() {
                let v = ALPHABET
                    .iter()
                    .position(|&a| a == c)
                    .expect("非法 base32 字符") as u32;
                acc = (acc << 5) | v;
                bits += 5;
                if bits >= 8 {
                    bits -= 8;
                    out.push((acc >> bits) as u8);
                }
                acc &= (1u32 << bits) - 1;
            }
            out
        }
        let cid = cid_v1(DEFAULT_BLOCK_CODEC, MH_SHA2_256, b"hello world").unwrap();
        assert!(cid.starts_with('b'), "multibase 前缀");
        let raw = decode(&cid[1..]);
        // [version][codec][mh_type][mh_len][32 字节摘要]
        assert_eq!(raw[0], 1);
        assert_eq!(raw[1], 0x55);
        assert_eq!(raw[2], 0x12);
        assert_eq!(raw[3], 32);
        assert_eq!(raw.len(), 36);
        assert_eq!(
            hex::encode(&raw[4..]),
            hex::encode(Sha256::digest(b"hello world"))
        );
    }

    #[test]
    fn test_cid_v1_rejects_unknown_hash() {
        let e = cid_v1(DEFAULT_BLOCK_CODEC, 0x13, b"x").unwrap_err();
        assert!(e.contains("不支持的块哈希类型"), "{e}");
    }

    #[test]
    fn test_join_remote_path() {
        assert_eq!(join_remote_path("/", "a.bin"), "/a.bin");
        assert_eq!(join_remote_path("/0706", "a.bin"), "/0706/a.bin");
        assert_eq!(join_remote_path("/a/b/", "c.bin"), "/a/b/c.bin");
    }

    #[test]
    fn test_upload_task_from_json() {
        // 服务端的数字字段是字符串（protobuf json tag 带 `,string`）
        let v = json!({
            "created": false,
            "task": "t-1",
            "upload_address": "https://up.example.com",
            "block_size": "4194304",
            "block_codec": "85",
            "block_hash_type": "18",
        });
        let t = UploadTask::from_json(&v).unwrap();
        assert!(!t.created);
        assert_eq!(t.task, "t-1");
        assert_eq!(t.block_size, 4 * 1024 * 1024);
        assert_eq!(t.block_codec, 0x55);
        assert_eq!(t.block_hash_type, 0x12);

        // 数字形态 + 缺省字段（0/缺省 → 用默认块参数）
        let v = json!({ "task": "t-2", "upload_address": "u", "block_size": 1024 });
        let t = UploadTask::from_json(&v).unwrap();
        assert_eq!(t.block_size, 1024);
        assert_eq!(t.block_codec, DEFAULT_BLOCK_CODEC);
        assert_eq!(t.block_hash_type, MH_SHA2_256);

        // 秒传：created=true 时任务字段可以为空
        let t = UploadTask::from_json(&json!({ "created": true })).unwrap();
        assert!(t.created);

        // 既没有 task 也没 upload_address → 报错并带上服务端 message
        let e = UploadTask::from_json(&json!({ "message": "quota exceeded" })).unwrap_err();
        assert!(e.contains("quota exceeded"), "{e}");
    }
}
