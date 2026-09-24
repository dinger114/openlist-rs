use super::DownloadInfo;
use crate::config::{Entry, Store};
use base64::Engine;
use md5::{Digest, Md5};
use reqwest::Client;
use serde_json::{json, Value};
use sha1::Sha1;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use uuid::Uuid;

const QUARK_API: &str = "https://drive.quark.cn/1/clouddrive";
const QUARK_REFERER: &str = "https://pan.quark.cn";
const QUARK_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) quark-cloud-drive/2.5.20 Chrome/100.0.4896.160 Electron/18.3.5.4-b478491100 Safari/537.36 Channel/pckk_other_ch";
const QUARK_PR: &str = "ucpro";

/// 对齐 Go 版 quark_uc/meta.go：UC 与夸克完全同源，仅域名/UA/pr 不同
pub const UC_CONF: Conf = Conf {
    api: "https://pc-api.uc.cn/1/clouddrive",
    referer: "https://drive.uc.cn",
    ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) uc-cloud-drive/2.5.20 Chrome/100.0.4896.160 Electron/18.3.5.4-b478491100 Safari/537.36 Channel/pckk_other_ch",
    pr: "UCBrowser",
};

#[derive(Clone, Copy)]
pub struct Conf {
    pub api: &'static str,
    pub referer: &'static str,
    pub ua: &'static str,
    pub pr: &'static str,
}

impl Default for Conf {
    fn default() -> Self {
        Conf {
            api: QUARK_API,
            referer: QUARK_REFERER,
            ua: QUARK_UA,
            pr: QUARK_PR,
        }
    }
}

/// 对齐 Go 版：file_name 里的 HTML 实体反转义
fn html_unescape(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
}

/// 夸克 / UC 网盘（对齐 Go 版 drivers/quark_uc QuarkOrUC）
pub struct QuarkOrUC {
    account_id: String,
    http: Client,
    conf: Conf,
    cookie: Mutex<String>,
    store: Arc<Store>,
}

/// 对齐 Go 版 upPart/upCommit 中写死的 x-oss-user-agent
const OSS_UA: &str = "aliyun-sdk-js/6.6.1 Chrome 98.0.4758.80 on Windows 10 64-bit";

/// /file/upload/pre 返回的上传会话信息（对齐 Go 版 UpPreResp 用到的字段）
struct QuarkUpPre {
    task_id: String,
    upload_id: String,
    obj_key: String,
    bucket: String,
    upload_url: String,
    auth_info: String,
    callback: Value,
    part_size: u64,
}

impl QuarkOrUC {
    pub fn new(account_id: &str, cookie: String, store: Arc<Store>) -> Self {
        Self::with_conf(account_id, cookie, store, Conf::default())
    }

    pub fn new_uc(account_id: &str, cookie: String, store: Arc<Store>) -> Self {
        Self::with_conf(account_id, cookie, store, UC_CONF)
    }

    pub fn with_conf(account_id: &str, cookie: String, store: Arc<Store>, conf: Conf) -> Self {
        QuarkOrUC {
            account_id: account_id.to_string(),
            http: Client::new(),
            conf,
            cookie: Mutex::new(cookie),
            store,
        }
    }

    fn cookie(&self) -> String {
        self.cookie.lock().unwrap().clone()
    }

    /// 响应 Set-Cookie 里的 __puus 会滚动更新，必须回写，否则旧 cookie 很快失效
    fn absorb_set_cookies(&self, resp: &reqwest::Response) {
        let mut updated: Option<String> = None;
        for v in resp.headers().get_all(reqwest::header::SET_COOKIE) {
            if let Ok(s) = v.to_str() {
                for pair in s.split(';') {
                    let mut it = pair.splitn(2, '=');
                    let k = it.next().unwrap_or("").trim();
                    let val = it.next().unwrap_or("").trim();
                    if k == "__puus" && !val.is_empty() {
                        updated = Some(val.to_string());
                    }
                }
            }
        }
        if let Some(puus) = updated {
            let mut c = self.cookie.lock().unwrap();
            let new_cookie = replace_cookie_value(&c, "__puus", &puus);
            *c = new_cookie;
            let snapshot = c.clone();
            let id = self.account_id.clone();
            let is_uc = self.conf.api == UC_CONF.api;
            self.store.update_credential(&id, |cred| match cred {
                crate::config::Credential::Quark { cookie } => *cookie = snapshot.clone(),
                crate::config::Credential::QuarkUC { cookie } if is_uc => {
                    *cookie = snapshot.clone()
                }
                _ => {}
            });
        }
    }

    /// 统一请求入口，对齐 Go 版 request()
    async fn request(
        &self,
        method: reqwest::Method,
        pathname: &str,
        query: Option<&[(&str, &str)]>,
        body: Option<Value>,
    ) -> Result<Value, String> {
        let url = format!("{}{}", self.conf.api, pathname);
        let mut req = self
            .http
            .request(method, &url)
            .query(&[("pr", self.conf.pr), ("fr", "pc")])
            .header("Cookie", self.cookie())
            .header("Accept", "application/json, text/plain, */*")
            .header("Referer", self.conf.referer)
            .header("User-Agent", self.conf.ua);
        if let Some(q) = query {
            req = req.query(q);
        }
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req.send().await.map_err(|e| format!("请求失败: {e}"))?;
        self.absorb_set_cookies(&resp);
        let status = resp.status();
        let json: Value = resp
            .json()
            .await
            .map_err(|e| format!("响应解析失败: {e}"))?;
        let code = json.get("code").and_then(|v| v.as_i64()).unwrap_or(-1);
        if status.as_u16() >= 400 || code != 0 {
            let msg = json
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error");
            return Err(format!("接口错误(code={code}): {msg}"));
        }
        Ok(json)
    }

    /// 对齐 Go 版 Init(): GET /config 验证 cookie 有效性
    pub async fn validate(&self) -> Result<(), String> {
        self.request(reqwest::Method::GET, "/config", None, None)
            .await?;
        Ok(())
    }

    /// 对齐 Go 版 GetFiles(): GET /file/sort 分页拉取
    pub async fn list(&self, parent_fid: &str) -> Result<Vec<Entry>, String> {
        let mut files = Vec::new();
        let mut page: u32 = 1;
        let size: u32 = 100;
        loop {
            let query: Vec<(String, String)> = vec![
                ("pdir_fid".into(), parent_fid.to_string()),
                ("_size".into(), size.to_string()),
                ("_page".into(), page.to_string()),
                ("_fetch_total".into(), "1".into()),
                ("fetch_all_file".into(), "1".into()),
                ("fetch_risk_file_name".into(), "1".into()),
            ];
            let refs: Vec<(&str, &str)> = query
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            let resp = self
                .request(reqwest::Method::GET, "/file/sort", Some(&refs), None)
                .await?;
            let list = resp
                .pointer("/data/list")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            for f in &list {
                let name = f
                    .get("file_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                files.push(Entry {
                    fid: f
                        .get("fid")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    name: html_unescape(&name),
                    size: f.get("size").and_then(|v| v.as_u64()).unwrap_or(0),
                    is_dir: !f.get("file").and_then(|v| v.as_bool()).unwrap_or(true),
                    updated_at: f.get("updated_at").and_then(|v| v.as_i64()),
                    etag: None,
                    s3_key_flag: None,
                    file_type: None,
                    extra: None,
                });
            }
            let total = resp
                .pointer("/metadata/_total")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32;
            if page * size >= total || list.is_empty() {
                break;
            }
            page += 1;
        }
        Ok(files)
    }

    /// 对齐 Go 版 getDownloadLink(): POST /file/download
    /// 直链需要带 Cookie/Referer/UA 才能访问，因此标记 proxy
    pub async fn download(&self, e: &Entry) -> Result<DownloadInfo, String> {
        let resp = self
            .request(
                reqwest::Method::POST,
                "/file/download",
                None,
                Some(json!({ "fids": [e.fid] })),
            )
            .await?;
        let url = resp
            .pointer("/data/0/download_url")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if url.is_empty() {
            return Err("未返回下载直链".into());
        }
        Ok(DownloadInfo {
            url,
            headers: vec![
                ("Cookie".into(), self.cookie()),
                ("Referer".into(), self.conf.referer.into()),
                ("User-Agent".into(), self.conf.ua.into()),
            ],
            proxy: true,
            local_path: None,
        })
    }

    /// 对齐 Go 版 MakeDir(): POST /file
    /// 同名冲突时 Go 版先 sleep 1s 再返回 ObjectAlreadyExists
    pub async fn mkdir(&self, parent_fid: &str, name: &str) -> Result<(), String> {
        let data = json!({
            "dir_init_lock": false,
            "dir_path": "",
            "file_name": name,
            "pdir_fid": parent_fid,
        });
        match self
            .request(reqwest::Method::POST, "/file", None, Some(data))
            .await
        {
            Ok(_) => {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                Ok(())
            }
            Err(e) if e.contains("file is doloading") => {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                Err("对象已存在".into())
            }
            Err(e) => Err(e),
        }
    }

    /// 对齐 Go 版 Rename(): POST /file/rename
    pub async fn rename(&self, parent_fid: &str, e: &Entry, new_name: &str) -> Result<(), String> {
        let _ = parent_fid;
        let data = json!({
            "fid": e.fid,
            "file_name": new_name,
        });
        self.request(reqwest::Method::POST, "/file/rename", None, Some(data))
            .await?;
        Ok(())
    }

    /// 对齐 Go 版 Move(): POST /file/move
    pub async fn move_entry(
        &self,
        parent_fid: &str,
        e: &Entry,
        dst_dir_fid: &str,
    ) -> Result<(), String> {
        let _ = parent_fid;
        let data = json!({
            "action_type": 1,
            "exclude_fids": [],
            "filelist": [e.fid],
            "to_pdir_fid": dst_dir_fid,
        });
        self.request(reqwest::Method::POST, "/file/move", None, Some(data))
            .await?;
        Ok(())
    }

    /// 对齐 Go 版 Copy(): errs.NotSupport
    pub async fn copy(&self, parent_fid: &str, e: &Entry, dst_dir_fid: &str) -> Result<(), String> {
        let _ = parent_fid;
        let _ = e;
        let _ = dst_dir_fid;
        Err("夸克网盘不支持复制操作".into())
    }

    /// 对齐 Go 版 Remove(): POST /file/delete
    pub async fn remove(&self, parent_fid: &str, e: &Entry) -> Result<(), String> {
        let _ = parent_fid;
        let data = json!({
            "action_type": 1,
            "exclude_fids": [],
            "filelist": [e.fid],
        });
        self.request(reqwest::Method::POST, "/file/delete", None, Some(data))
            .await?;
        Ok(())
    }

    /// 对齐 Go 版 Put()：算 md5+sha1 -> /file/upload/pre 预检 -> /file/update/hash 秒传
    /// -> OSS 分片 PUT（/file/upload/auth 取签名）-> XML 合并 -> /file/upload/finish。
    /// 两个 hash 都要全量内容且分片重试需重读 -> 先落临时文件边写边算。
    pub async fn put(&self, dst_dir_fid: &str, input: super::PutInput) -> Result<(), String> {
        let tmp_path = temp_file_path();
        let _guard = TempFileGuard(tmp_path.clone());
        let (size, md5_str, sha1_str) = spool_md5_sha1(input.reader, &tmp_path).await?;
        let mime = mime_of(&input.name);

        // pre：对齐 Go 版 upPre()
        let now_ms = now_ms() as i64;
        let pre_v = self
            .request(
                reqwest::Method::POST,
                "/file/upload/pre",
                None,
                Some(json!({
                    "ccp_hash_update": true,
                    "dir_name": "",
                    "file_name": input.name,
                    "format_type": mime,
                    "l_created_at": now_ms,
                    "l_updated_at": now_ms,
                    "pdir_fid": dst_dir_fid,
                    "size": size as i64,
                })),
            )
            .await?;
        let get_s = |v: &Value, p: &str| {
            v.pointer(p)
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string()
        };
        let mut pre = QuarkUpPre {
            task_id: get_s(&pre_v, "/data/task_id"),
            upload_id: get_s(&pre_v, "/data/upload_id"),
            obj_key: get_s(&pre_v, "/data/obj_key"),
            bucket: get_s(&pre_v, "/data/bucket"),
            upload_url: get_s(&pre_v, "/data/upload_url"),
            auth_info: get_s(&pre_v, "/data/auth_info"),
            callback: pre_v
                .pointer("/data/callback")
                .cloned()
                .unwrap_or(Value::Null),
            // 对齐 Go 版直接使用 metadata.part_size；缺失/为 0 时兜底 16MB 防止除零
            part_size: {
                let ps = pre_v
                    .pointer("/metadata/part_size")
                    .and_then(|x| x.as_u64())
                    .unwrap_or(16 * 1024 * 1024);
                if ps == 0 {
                    16 * 1024 * 1024
                } else {
                    ps
                }
            },
        };
        if pre.task_id.is_empty() {
            return Err("夸克上传预检失败: 未返回 task_id".into());
        }
        pre.upload_url = pre.upload_url.trim_end_matches('/').to_string();

        // hash：对齐 Go 版 upHash()，finish=true 即秒传完成
        let hash_v = self
            .request(
                reqwest::Method::POST,
                "/file/update/hash",
                None,
                Some(json!({
                    "md5": md5_str,
                    "sha1": sha1_str,
                    "task_id": pre.task_id,
                })),
            )
            .await?;
        if hash_v
            .pointer("/data/finish")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            return Ok(());
        }
        // 非秒传才需要 OSS 分片信息
        if pre.upload_url.is_empty() || pre.bucket.is_empty() || pre.obj_key.is_empty() {
            return Err("夸克上传预检失败: 缺少 OSS 上传信息".into());
        }

        // 分片上传：对齐 Go 版主循环（partNumber 从 1 开始）
        let total = size;
        let part_size = pre.part_size;
        let upload_nums = total.div_ceil(part_size);
        let mut md5s: Vec<String> = Vec::new();
        for part_index in 0..upload_nums {
            let offset = part_index * part_size;
            let chunk = std::cmp::min(part_size, total - offset);
            let etag = self
                .up_part(
                    &pre,
                    &mime,
                    (part_index + 1) as i64,
                    &tmp_path,
                    offset,
                    chunk,
                )
                .await?;
            md5s.push(etag);
        }

        // 合并 + finish：对齐 Go 版 upCommit() / upFinish()
        self.up_commit(&pre, &md5s).await?;
        self.up_finish(&pre).await
    }

    /// 对齐 Go 版 upPart()：请求 /file/upload/auth 取签名后 PUT 到 OSS
    async fn up_part(
        &self,
        pre: &QuarkUpPre,
        mime: &str,
        part_number: i64,
        tmp: &Path,
        offset: u64,
        len: u64,
    ) -> Result<String, String> {
        let host = pre
            .upload_url
            .strip_prefix("http://")
            .unwrap_or(&pre.upload_url);
        let mut last_err = String::new();
        for attempt in 0..3u64 {
            if attempt > 0 {
                // 对齐 Go retry.BackOffDelay：1s、2s
                tokio::time::sleep(std::time::Duration::from_secs(1 << (attempt - 1))).await;
            }
            let data = read_temp_part(tmp, offset, len).await?;
            let time_str = http_time_now();
            let auth_meta = format!(
                "PUT\n\n{}\n{}\nx-oss-date:{}\nx-oss-user-agent:{}\n/{}/{}?partNumber={}&uploadId={}",
                mime, time_str, time_str, OSS_UA, pre.bucket, pre.obj_key, part_number, pre.upload_id
            );
            let auth = self
                .request(
                    reqwest::Method::POST,
                    "/file/upload/auth",
                    None,
                    Some(json!({
                        "auth_info": pre.auth_info,
                        "auth_meta": auth_meta,
                        "task_id": pre.task_id,
                    })),
                )
                .await?;
            let auth_key = auth
                .pointer("/data/auth_key")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if auth_key.is_empty() {
                last_err = "夸克分片签名失败: 未返回 auth_key".into();
                continue;
            }
            let url = format!("https://{}.{}/{}", pre.bucket, host, pre.obj_key);
            let resp = self
                .http
                .put(&url)
                .query(&[
                    ("partNumber", part_number.to_string()),
                    ("uploadId", pre.upload_id.clone()),
                ])
                .header("Authorization", &auth_key)
                .header("Content-Type", mime)
                .header("Referer", "https://pan.quark.cn/")
                .header("x-oss-date", &time_str)
                .header("x-oss-user-agent", OSS_UA)
                .body(data)
                .send()
                .await;
            match resp {
                Ok(r) => {
                    let status = r.status().as_u16();
                    if status != 200 {
                        let t = r.text().await.unwrap_or_default();
                        last_err = format!(
                            "夸克分片上传失败: status={status}, body={}",
                            &t[..t.len().min(200)]
                        );
                        continue;
                    }
                    let etag = r
                        .headers()
                        .get("etag")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();
                    if etag.is_empty() {
                        last_err = "夸克分片上传失败: 响应缺少 Etag".into();
                        continue;
                    }
                    return Ok(etag);
                }
                Err(e) => last_err = format!("夸克分片上传失败: {e}"),
            }
        }
        Err(last_err)
    }

    /// 对齐 Go 版 upCommit()：XML CompleteMultipartUpload POST 回 OSS（带 callback）
    async fn up_commit(&self, pre: &QuarkUpPre, md5s: &[String]) -> Result<(), String> {
        let time_str = http_time_now();
        let mut body =
            String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<CompleteMultipartUpload>\n");
        for (i, m) in md5s.iter().enumerate() {
            body.push_str(&format!(
                "<Part>\n<PartNumber>{}</PartNumber>\n<ETag>{}</ETag>\n</Part>\n",
                i + 1,
                m
            ));
        }
        body.push_str("</CompleteMultipartUpload>");
        let mut mh = Md5::new();
        mh.update(body.as_bytes());
        let content_md5 = base64::engine::general_purpose::STANDARD.encode(mh.finalize());
        let callback_bytes = serde_json::to_vec(&pre.callback)
            .map_err(|e| format!("夸克上传回调序列化失败: {e}"))?;
        let callback_b64 = base64::engine::general_purpose::STANDARD.encode(callback_bytes);
        let auth_meta = format!(
            "POST\n{}\napplication/xml\n{}\nx-oss-callback:{}\nx-oss-date:{}\nx-oss-user-agent:{}\n/{}/{}?uploadId={}",
            content_md5, time_str, callback_b64, time_str, OSS_UA, pre.bucket, pre.obj_key, pre.upload_id
        );
        let auth = self
            .request(
                reqwest::Method::POST,
                "/file/upload/auth",
                None,
                Some(json!({
                    "auth_info": pre.auth_info,
                    "auth_meta": auth_meta,
                    "task_id": pre.task_id,
                })),
            )
            .await?;
        let auth_key = auth
            .pointer("/data/auth_key")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if auth_key.is_empty() {
            return Err("夸克分片合并签名失败: 未返回 auth_key".into());
        }
        let host = pre
            .upload_url
            .strip_prefix("http://")
            .unwrap_or(&pre.upload_url);
        let url = format!("https://{}.{}/{}", pre.bucket, host, pre.obj_key);
        let resp = self
            .http
            .post(&url)
            .query(&[("uploadId", pre.upload_id.clone())])
            .header("Authorization", &auth_key)
            .header("Content-MD5", &content_md5)
            .header("Content-Type", "application/xml")
            .header("Referer", "https://pan.quark.cn/")
            .header("x-oss-callback", &callback_b64)
            .header("x-oss-date", &time_str)
            .header("x-oss-user-agent", OSS_UA)
            .body(body)
            .send()
            .await
            .map_err(|e| format!("夸克分片合并失败: {e}"))?;
        let status = resp.status().as_u16();
        if status != 200 {
            let t = resp.text().await.unwrap_or_default();
            return Err(format!(
                "夸克分片合并失败: status={status}, body={}",
                &t[..t.len().min(200)]
            ));
        }
        Ok(())
    }

    /// 对齐 Go 版 upFinish()：POST /file/upload/finish 后 sleep 1s
    async fn up_finish(&self, pre: &QuarkUpPre) -> Result<(), String> {
        self.request(
            reqwest::Method::POST,
            "/file/upload/finish",
            None,
            Some(json!({
                "obj_key": pre.obj_key,
                "task_id": pre.task_id,
            })),
        )
        .await?;
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        Ok(())
    }
}

/// 把 cookie 字符串里 name=value 的 value 替换为 new_value；不存在则追加
fn replace_cookie_value(cookie: &str, name: &str, new_value: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut found = false;
    for pair in cookie.split(';') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let key = pair.split('=').next().unwrap_or("").trim();
        if key == name {
            found = true;
            out.push(format!("{name}={new_value}"));
        } else {
            out.push(pair.to_string());
        }
    }
    if !found {
        out.push(format!("{name}={new_value}"));
    }
    out.join("; ")
}

// ---------- 上传辅助 ----------

/// 临时文件守卫：Drop 时必定删除临时文件（无论成功失败路径）
struct TempFileGuard(PathBuf);

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn temp_file_path() -> PathBuf {
    std::env::temp_dir().join(format!("openlist-rs-quark-{}", Uuid::new_v4()))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Howard Hinnant civil_from_days：epoch 天数 -> (年, 月, 日)
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m as u32, d as u32)
}

/// 当前 UTC 时间的 HTTP 日期格式（对齐 Go http.TimeFormat："Mon, 02 Jan 2006 15:04:05 GMT"）
fn http_time_now() -> String {
    const WD: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MO: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    // 1970-01-01 是星期四，WD 从 Thu 开始
    let wd = WD[(days.rem_euclid(7)) as usize];
    let (y, m, d) = civil_from_days(days);
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} GMT",
        wd,
        d,
        MO[(m - 1) as usize],
        y,
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// 按文件扩展名猜测 Content-Type（对齐 Go 版 file.GetMimetype()，未知类型 octet-stream）
fn mime_of(name: &str) -> String {
    let ext = std::path::Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        "mp4" => "video/mp4",
        "mkv" => "video/x-matroska",
        "avi" => "video/x-msvideo",
        "mov" => "video/quicktime",
        "wmv" => "video/x-ms-wmv",
        "flv" => "video/x-flv",
        "ts" => "video/mp2t",
        "webm" => "video/webm",
        "m4v" => "video/x-m4v",
        "3gp" => "video/3gpp",
        "mp3" => "audio/mpeg",
        "flac" => "audio/flac",
        "wav" => "audio/wav",
        "aac" => "audio/aac",
        "ogg" => "audio/ogg",
        "m4a" => "audio/mp4",
        "ape" => "audio/ape",
        "wma" => "audio/x-ms-wma",
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "bmp" => "image/bmp",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "heic" => "image/heic",
        "txt" => "text/plain",
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "csv" => "text/csv",
        "json" => "application/json",
        "xml" => "application/xml",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "rar" => "application/x-rar-compressed",
        "7z" => "application/x-7z-compressed",
        "tar" => "application/x-tar",
        "gz" => "application/gzip",
        "iso" => "application/x-iso9660-image",
        "apk" => "application/vnd.android.package-archive",
        "exe" => "application/x-msdownload",
        "doc" => "application/msword",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xls" => "application/vnd.ms-excel",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "ppt" => "application/vnd.ms-powerpoint",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "torrent" => "application/x-bittorrent",
        _ => "application/octet-stream",
    }
    .to_string()
}

/// 把上传流落到临时文件，同时计算整文件 md5 与 sha1（对齐 Go 版 Put 里 CacheFullAndWriter 的双 hash）
async fn spool_md5_sha1(
    mut reader: std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send>>,
    path: &Path,
) -> Result<(u64, String, String), String> {
    let mut f = tokio::fs::File::create(path)
        .await
        .map_err(|e| format!("夸克创建临时文件失败: {e}"))?;
    let mut md5h = Md5::new();
    let mut sha1h = Sha1::new();
    let mut buf = vec![0u8; 256 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = reader
            .read(&mut buf)
            .await
            .map_err(|e| format!("夸克读取上传流失败: {e}"))?;
        if n == 0 {
            break;
        }
        f.write_all(&buf[..n])
            .await
            .map_err(|e| format!("夸克写入临时文件失败: {e}"))?;
        md5h.update(&buf[..n]);
        sha1h.update(&buf[..n]);
        total += n as u64;
    }
    f.flush()
        .await
        .map_err(|e| format!("夸克临时文件落盘失败: {e}"))?;
    Ok((
        total,
        hex::encode(md5h.finalize()),
        hex::encode(sha1h.finalize()),
    ))
}

/// 从临时文件读取指定区间（分片重试时每次重读）
async fn read_temp_part(path: &Path, offset: u64, len: u64) -> Result<Vec<u8>, String> {
    let mut f = tokio::fs::File::open(path)
        .await
        .map_err(|e| format!("夸克打开临时文件失败: {e}"))?;
    f.seek(std::io::SeekFrom::Start(offset))
        .await
        .map_err(|e| format!("夸克临时文件 seek 失败: {e}"))?;
    let mut buf = vec![0u8; len as usize];
    f.read_exact(&mut buf)
        .await
        .map_err(|e| format!("夸克读取临时分片失败: {e}"))?;
    Ok(buf)
}
