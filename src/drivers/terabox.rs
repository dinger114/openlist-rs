//! Terabox 驱动（对齐 Go 版 drivers/terabox，国际版百度网盘）
//!
//! - Cookie 授权；首次请求自动从首页抓 jsToken（errno 4000023/450016 时重抓重试）
//! - 下载：official = /api/download + sign（RC4 变种签名）→ 302 后的直链需带 UA；
//!   crack = /api/filemetas 直接拿 dlink
//! - 上传：precreate → 分片上传（4MB，md5 校验）→ create，对齐 Go 版
//! - Entry.fid = fs_id；文件 path 存 extra 供 crack 直链使用

use super::{DownloadInfo, PutInput};
use crate::config::Entry;
use base64::Engine;
use md5::{Digest, Md5};
use reqwest::Client;
use serde_json::{json, Value};
use std::sync::Mutex;

const UA: &str = "terabox;1.37.0.7;PC;PC-Windows;10.0.22631;WindowsTeraBox";
const INITIAL_CHUNK_SIZE: u64 = 4 << 20; // 4MB

pub struct Terabox {
    cookie: String,
    download_api: String,
    root_path: String,
    http: Client,
    /// jsToken（errno 失效时自动重抓）
    js_token: Mutex<String>,
    /// url_domain_prefix，errno -6 时按响应头重定向
    base_url: Mutex<String>,
}

impl Terabox {
    pub fn new(cookie: String, download_api: String, root_path: String) -> Self {
        Terabox {
            cookie,
            download_api: if download_api.is_empty() {
                "official".into()
            } else {
                download_api
            },
            root_path: if root_path.trim().is_empty() || root_path.trim() == "0" {
                "/".into()
            } else {
                root_path.trim().to_string()
            },
            http: Client::new(),
            js_token: Mutex::new(String::new()),
            base_url: Mutex::new("https://www.terabox.com".into()),
        }
    }

    /// 从首页 HTML 抓 jsToken（对齐 Go 版 resetJsToken）
    async fn reset_js_token(&self) -> Result<(), String> {
        let base = self.base_url.lock().unwrap().clone();
        let resp = self
            .http
            .get(&base)
            .header("Cookie", &self.cookie)
            .header("User-Agent", UA)
            .header("Referer", &base)
            .header("X-Requested-With", "XMLHttpRequest")
            .send()
            .await
            .map_err(|e| format!("Terabox 获取 jsToken 失败: {e}"))?;
        let html = resp.text().await.unwrap_or_default();
        let token = get_str_between(
            &html,
            "`function%20fn%28a%29%7Bwindow.jsToken%20%3D%20a%7D%3Bfn%28%22",
            "%22%29`",
        );
        if token.is_empty() {
            return Err("Terabox 未能从首页抓到 jsToken，请检查 cookie 是否有效".into());
        }
        *self.js_token.lock().unwrap() = token;
        Ok(())
    }

    /// 统一请求（对齐 Go 版 request：errno 4000023/450016 重抓 jsToken 重试一次）
    async fn request(
        &self,
        method: reqwest::Method,
        url_or_path: &str,
        query: Option<Vec<(String, String)>>,
        form: Option<Vec<(String, String)>>,
        body: Option<String>,
    ) -> Result<Value, String> {
        let full_url = if url_or_path.starts_with("https://") {
            url_or_path.to_string()
        } else {
            format!("{}{url_or_path}", self.base_url.lock().unwrap().clone())
        };
        let send = |method: reqwest::Method,
                    query: Option<Vec<(String, String)>>,
                    form: Option<Vec<(String, String)>>,
                    body: Option<String>,
                    js_token: String| {
            let mut req = self
                .http
                .request(method, &full_url)
                .header("Cookie", &self.cookie)
                .header("User-Agent", UA)
                .header("Referer", self.base_url.lock().unwrap().clone())
                .header("X-Requested-With", "XMLHttpRequest")
                .query(&[
                    ("app_id", "250528"),
                    ("web", "1"),
                    ("channel", "dubox"),
                    ("clienttype", "0"),
                    ("jsToken", js_token.as_str()),
                ]);
            if let Some(q) = &query {
                req = req.query(q);
            }
            if let Some(f) = &form {
                req = req.form(f);
            }
            if let Some(b) = &body {
                req = req.header("Content-Type", "text/plain").body(b.clone());
            }
            req
        };
        if self.js_token.lock().unwrap().is_empty() {
            self.reset_js_token().await?;
        }
        // MutexGuard 临时值不能活过 .await（future 必须 Send），先取出 clone
        let js_token = self.js_token.lock().unwrap().clone();
        let resp = send(
            method.clone(),
            query.clone(),
            form.clone(),
            body.clone(),
            js_token,
        )
        .send()
        .await
        .map_err(|e| format!("Terabox 请求失败: {e}"))?;
        // errno -6：按 Url-Domain-Prefix 重定向 base_url 后重试
        let prefix = resp
            .headers()
            .get("Url-Domain-Prefix")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let text = resp.text().await.unwrap_or_default();
        let v: Value = serde_json::from_str(&text).unwrap_or(json!({}));
        let errno = v.get("errno").and_then(|e| e.as_i64()).unwrap_or(0);
        if errno == -6 && !prefix.is_empty() {
            *self.base_url.lock().unwrap() = format!("https://{prefix}.terabox.com");
            return Box::pin(self.request(method, url_or_path, query, form, body)).await;
        }
        if errno == 4000023 || errno == 450016 {
            self.reset_js_token().await?;
            let js_token = self.js_token.lock().unwrap().clone();
            let resp = send(method, query, form, body, js_token)
                .send()
                .await
                .map_err(|e| format!("Terabox 请求失败: {e}"))?;
            let text = resp.text().await.unwrap_or_default();
            return serde_json::from_str(&text).map_err(|e| format!("Terabox 响应解析失败: {e}"));
        }
        Ok(v)
    }

    pub async fn validate(&self) -> Result<(), String> {
        let v = self
            .request(reqwest::Method::GET, "/api/check/login", None, None, None)
            .await?;
        let errno = v.get("errno").and_then(|e| e.as_i64()).unwrap_or(-1);
        if errno != 0 {
            if errno == 9000 {
                return Err("Terabox 在当前地区不可用".into());
            }
            return Err(format!("Terabox cookie 校验失败 (errno {errno})"));
        }
        Ok(())
    }

    fn resolve(&self, fid: &str) -> String {
        let fid = fid.trim();
        if fid.is_empty() || fid == "0" {
            self.root_path.clone()
        } else {
            fid.to_string()
        }
    }

    /// 分页列目录（对齐 Go 版 getFiles）
    async fn get_files(&self, dir: &str) -> Result<Vec<Value>, String> {
        let mut page = 1;
        let num = 100;
        let mut out = Vec::new();
        loop {
            let v = self
                .request(
                    reqwest::Method::GET,
                    "/api/list",
                    Some(vec![
                        ("dir".into(), dir.to_string()),
                        ("page".into(), page.to_string()),
                        ("num".into(), num.to_string()),
                    ]),
                    None,
                    None,
                )
                .await?;
            let errno = v.get("errno").and_then(|e| e.as_i64()).unwrap_or(-1);
            if errno == 9000 {
                return Err("Terabox 在当前地区不可用".into());
            }
            if errno != 0 {
                return Err(format!("Terabox 列表失败 (errno {errno})"));
            }
            let list = v
                .get("list")
                .and_then(|l| l.as_array())
                .cloned()
                .unwrap_or_default();
            if list.is_empty() {
                break;
            }
            let got = list.len();
            out.extend(list);
            page += 1;
            let _ = got;
        }
        Ok(out)
    }

    pub async fn list(&self, parent_fid: &str) -> Result<Vec<Entry>, String> {
        let dir = self.resolve(parent_fid);
        let files = self.get_files(&dir).await?;
        let mut out = Vec::new();
        for f in files {
            let name = f
                .get("server_filename")
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .to_string();
            if name.is_empty() {
                continue;
            }
            let is_dir = f.get("isdir").and_then(|d| d.as_i64()) == Some(1);
            let size = f.get("size").and_then(|s| s.as_u64()).unwrap_or(0);
            let fs_id = f
                .get("fs_id")
                .and_then(|i| i.as_i64())
                .unwrap_or(0)
                .to_string();
            let path = f
                .get("path")
                .and_then(|p| p.as_str())
                .unwrap_or("")
                .to_string();
            let mtime = f
                .get("server_mtime")
                .and_then(|m| m.as_i64())
                .map(|s| s * 1000);
            out.push(Entry {
                fid: fs_id,
                name,
                size: if is_dir { 0 } else { size },
                is_dir,
                updated_at: mtime,
                etag: None,
                s3_key_flag: None,
                file_type: None,
                extra: Some(json!({ "path": path })),
            });
        }
        Ok(out)
    }

    fn file_path(&self, e: &Entry) -> String {
        e.extra
            .as_ref()
            .and_then(|x| x.get("path"))
            .and_then(|p| p.as_str())
            .unwrap_or("")
            .to_string()
    }

    /// RC4 变种签名（对齐 Go 版 sign）
    fn rc4_sign(s1: &str, s2: &str) -> String {
        let mut a = [0u32; 256];
        let mut p = [0u32; 256];
        let s1b = s1.as_bytes();
        let v = s1b.len();
        for q in 0..256 {
            a[q] = s1b[q % v] as u32;
            p[q] = q as u32;
        }
        let mut u = 0u32;
        for q in 0..256 {
            u = (u + p[q] + a[q]) % 256;
            p.swap(q, u as usize);
        }
        let mut o: Vec<u8> = Vec::with_capacity(s2.len());
        let (mut i, mut u2) = (0u32, 0u32);
        for (q, ch) in s2.bytes().enumerate() {
            i = (i + 1) % 256;
            u2 = (u2 + p[i as usize]) % 256;
            p.swap(i as usize, u2 as usize);
            let k = p[((p[i as usize] + p[u2 as usize]) % 256) as usize];
            o.push(ch ^ (k as u8));
            let _ = q;
        }
        base64::engine::general_purpose::STANDARD.encode(o)
    }

    async fn gen_sign(&self) -> Result<String, String> {
        let v = self
            .request(reqwest::Method::GET, "/api/home/info", None, None, None)
            .await?;
        let sign3 = v
            .pointer("/data/sign3")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string();
        let sign1 = v
            .pointer("/data/sign1")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string();
        Ok(Self::rc4_sign(&sign3, &sign1))
    }

    pub async fn download(&self, e: &Entry) -> Result<DownloadInfo, String> {
        if e.is_dir {
            return Err("目录无法下载".into());
        }
        if self.download_api == "crack" {
            // /api/filemetas 直链
            let path = self.file_path(e);
            if path.is_empty() {
                return Err("Terabox crack 直链需要文件 path（请重新刷新目录）".into());
            }
            let v = self
                .request(
                    reqwest::Method::GET,
                    "/api/filemetas",
                    Some(vec![
                        ("target".into(), format!("[\"{}\"]", path)),
                        ("dlink".into(), "1".into()),
                        ("origin".into(), "dlna".into()),
                    ]),
                    None,
                    None,
                )
                .await?;
            let url = v
                .pointer("/info/0/dlink")
                .and_then(|u| u.as_str())
                .unwrap_or("")
                .to_string();
            if url.is_empty() {
                return Err("Terabox 未返回 dlink".into());
            }
            return Ok(DownloadInfo {
                url,
                headers: vec![("User-Agent".into(), UA.into())],
                proxy: true,
                local_path: None,
            });
        }
        // official：/api/download + sign → 302 解析最终直链
        let sign = self.gen_sign().await?;
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let v = self
            .request(
                reqwest::Method::GET,
                "/api/download",
                Some(vec![
                    ("type".into(), "dlink".into()),
                    ("fidlist".into(), format!("[{}]", e.fid)),
                    ("sign".into(), sign),
                    ("vip".into(), "2".into()),
                    ("timestamp".into(), ts.to_string()),
                ]),
                None,
                None,
            )
            .await?;
        let dlink = v
            .pointer("/dlink/0/dlink")
            .and_then(|u| u.as_str())
            .unwrap_or("")
            .to_string();
        if dlink.is_empty() {
            return Err("Terabox 未返回 dlink".into());
        }
        // 请求 dlink 拿 302 location
        let resp = self
            .http
            .get(&dlink)
            .header("Cookie", &self.cookie)
            .header("User-Agent", UA)
            .send()
            .await
            .map_err(|e| format!("Terabox 解析直链失败: {e}"))?;
        let final_url = resp.url().clone();
        Ok(DownloadInfo {
            url: final_url.to_string(),
            headers: vec![("User-Agent".into(), UA.into())],
            proxy: true,
            local_path: None,
        })
    }

    pub async fn mkdir(&self, parent_fid: &str, name: &str) -> Result<(), String> {
        let path = format!(
            "{}/{}",
            self.resolve(parent_fid).trim_end_matches('/'),
            name.trim_matches('/')
        );
        let v = self
            .request(
                reqwest::Method::POST,
                "/api/create",
                Some(vec![("a".into(), "commit".into())]),
                Some(vec![
                    ("path".into(), path),
                    ("isdir".into(), "1".into()),
                    ("block_list".into(), "[]".into()),
                ]),
                None,
            )
            .await?;
        let errno = v.get("errno").and_then(|e| e.as_i64()).unwrap_or(-1);
        if errno != 0 {
            return Err(format!("Terabox 创建文件夹失败 (errno {errno})"));
        }
        Ok(())
    }

    async fn manage(&self, opera: &str, filelist: String) -> Result<(), String> {
        let data = format!("async=0&filelist={}&ondup=newcopy", urlencode(&filelist));
        let v = self
            .request(
                reqwest::Method::POST,
                "/api/filemanager",
                Some(vec![
                    ("onnest".into(), "fail".into()),
                    ("opera".into(), opera.into()),
                ]),
                None,
                Some(data),
            )
            .await?;
        let errno = v.get("errno").and_then(|e| e.as_i64()).unwrap_or(-1);
        if errno != 0 {
            return Err(format!("Terabox 操作失败 (errno {errno})"));
        }
        Ok(())
    }

    pub async fn rename(&self, _parent_fid: &str, e: &Entry, new_name: &str) -> Result<(), String> {
        let path = self.file_path(e);
        self.manage(
            "rename",
            format!("[{{\"path\":\"{path}\",\"newname\":\"{new_name}\"}}]"),
        )
        .await
    }

    pub async fn move_entry(
        &self,
        _parent_fid: &str,
        e: &Entry,
        dst_dir_fid: &str,
    ) -> Result<(), String> {
        let path = self.file_path(e);
        let dest = self.resolve(dst_dir_fid);
        self.manage(
            "move",
            format!(
                "[{{\"path\":\"{path}\",\"dest\":\"{dest}\",\"newname\":\"{}\"}}]",
                e.name
            ),
        )
        .await
    }

    pub async fn copy(
        &self,
        _parent_fid: &str,
        e: &Entry,
        dst_dir_fid: &str,
    ) -> Result<(), String> {
        let path = self.file_path(e);
        let dest = self.resolve(dst_dir_fid);
        self.manage(
            "copy",
            format!(
                "[{{\"path\":\"{path}\",\"dest\":\"{dest}\",\"newname\":\"{}\"}}]",
                e.name
            ),
        )
        .await
    }

    pub async fn remove(&self, _parent_fid: &str, e: &Entry) -> Result<(), String> {
        let path = self.file_path(e);
        self.manage("delete", format!("[\"{path}\"]")).await
    }

    pub async fn put(&self, dst_dir_fid: &str, mut input: PutInput) -> Result<(), String> {
        use tokio::io::AsyncReadExt;
        let target_path = self.resolve(dst_dir_fid);
        let raw_path = format!(
            "{}/{}",
            target_path.trim_end_matches('/'),
            input.name.trim_matches('/')
        );
        // 缓冲全部内容（分片需要按块读 + md5 校验）
        let mut buf = Vec::with_capacity(input.size as usize);
        let mut tmp = vec![0u8; 256 * 1024];
        loop {
            let n = input
                .reader
                .read(&mut tmp)
                .await
                .map_err(|e| format!("读上传流失败: {e}"))?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.len() as u64 > 4 * 1024 * 1024 * 1024 {
                return Err("Terabox 上传暂限 4GB".into());
            }
        }
        let stream_size = buf.len() as u64;
        // 1. precreate
        let block_list = if stream_size > INITIAL_CHUNK_SIZE {
            "[\"5910a591dd8fc18c32a8f3df4fdc1761\",\"a5fc157d78e6ad1c7e114b056c92821e\"]"
        } else {
            "[\"5910a591dd8fc18c32a8f3df4fdc1761\"]"
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let pre = self
            .request(
                reqwest::Method::POST,
                "/api/precreate",
                None,
                Some(vec![
                    ("path".into(), raw_path.clone()),
                    ("autoinit".into(), "1".into()),
                    ("target_path".into(), target_path.clone()),
                    ("block_list".into(), block_list.into()),
                    ("local_mtime".into(), now.to_string()),
                    ("file_limit_switch_v34".into(), "true".into()),
                ]),
                None,
            )
            .await?;
        let pre_errno = pre.get("errno").and_then(|e| e.as_i64()).unwrap_or(-1);
        if pre_errno != 0 {
            return Err(format!("Terabox precreate 失败 (errno {pre_errno})"));
        }
        if pre.get("return_type").and_then(|r| r.as_i64()) == Some(2) {
            // 秒传成功
            return Ok(());
        }
        let upload_id = pre
            .get("uploadid")
            .and_then(|u| u.as_str())
            .unwrap_or("")
            .to_string();
        if upload_id.is_empty() {
            return Err("Terabox precreate 未返回 uploadid".into());
        }
        // 2. 定位上传节点
        let locate = self
            .http
            .get("https://jp-data.terabox.com/rest/2.0/pcs/file?method=locateupload")
            .header("Cookie", &self.cookie)
            .header("User-Agent", UA)
            .send()
            .await
            .map_err(|e| format!("Terabox locateupload 失败: {e}"))?;
        let locate_v: Value = locate
            .json()
            .await
            .map_err(|e| format!("Terabox locateupload 解析失败: {e}"))?;
        let upload_host = locate_v
            .get("host")
            .and_then(|h| h.as_str())
            .unwrap_or("d.pcs.baidu.com")
            .to_string();
        // 3. 分片上传（4MB，md5 校验）
        let chunk_size = if stream_size < INITIAL_CHUNK_SIZE {
            stream_size
        } else {
            INITIAL_CHUNK_SIZE
        };
        let count = stream_size.div_ceil(chunk_size) as usize;
        let mut upload_block_list: Vec<String> = Vec::with_capacity(count);
        for partseq in 0..count {
            let start = partseq as u64 * chunk_size;
            let end = std::cmp::min(start + chunk_size, stream_size) as usize;
            let byte_data = &buf[start as usize..end];
            let mut h = Md5::new();
            h.update(byte_data);
            let local_md5 = hex::encode(h.finalize());
            let url = format!("https://{upload_host}/rest/2.0/pcs/superfile2");
            let form = reqwest::multipart::Form::new()
                .part(
                    "file",
                    reqwest::multipart::Part::bytes(byte_data.to_vec())
                        .file_name(input.name.clone()),
                )
                .text("path", raw_path.clone())
                .text("uploadid", upload_id.clone())
                .text("partseq", partseq.to_string());
            let resp = self
                .http
                .post(&url)
                .query(&[
                    ("method", "upload"),
                    ("app_id", "250528"),
                    ("clienttype", "0"),
                    ("web", "1"),
                    ("channel", "dubox"),
                ])
                .header("Cookie", &self.cookie)
                .header("User-Agent", UA)
                .multipart(form)
                .send()
                .await
                .map_err(|e| format!("Terabox 分片上传失败: {e}"))?;
            let text = resp.text().await.unwrap_or_default();
            let v: Value = serde_json::from_str(&text).unwrap_or(json!({}));
            let rsp_md5 = v.get("md5").and_then(|m| m.as_str()).unwrap_or("");
            if rsp_md5 != local_md5 {
                return Err(format!(
                    "Terabox 分片 {partseq} md5 校验不一致（本地 {local_md5} / 服务端 {rsp_md5}）"
                ));
            }
            upload_block_list.push(local_md5);
        }
        // 4. create
        let block_str = serde_json::to_string(&upload_block_list).unwrap_or_default();
        let create = self
            .request(
                reqwest::Method::POST,
                "/api/create",
                Some(vec![
                    ("isdir".into(), "0".into()),
                    ("rtype".into(), "1".into()),
                ]),
                Some(vec![
                    ("path".into(), raw_path),
                    ("size".into(), stream_size.to_string()),
                    ("uploadid".into(), upload_id),
                    ("target_path".into(), target_path),
                    ("block_list".into(), block_str),
                    ("local_mtime".into(), now.to_string()),
                ]),
                None,
            )
            .await?;
        let create_errno = create.get("errno").and_then(|e| e.as_i64()).unwrap_or(-1);
        if create_errno != 0 {
            return Err(format!("Terabox create 失败 (errno {create_errno})"));
        }
        Ok(())
    }
}

fn get_str_between(raw: &str, start: &str, end: &str) -> String {
    let s = match raw.find(start) {
        Some(i) => &raw[i + start.len()..],
        None => return String::new(),
    };
    match s.find(end) {
        Some(j) => s[..j].to_string(),
        None => String::new(),
    }
}

fn urlencode(s: &str) -> String {
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
