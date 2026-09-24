//! WebDAV 客户端驱动（对齐 Go 版 drivers/webdav，只做挂载其他 WebDAV 服务器）
//!
//! - fid 为相对配置根（url 路径 + root_path）的路径，以 / 开头；根目录 = ""/"0"/"/"
//!   （对齐 Go 版：gowebdav client 根 = Address，对象 path 相对 client 根做 URL join）
//! - list：PROPFIND Depth:1，容错解析 multistatus XML（不依赖 XML 库）
//! - download：GET 路径，直链与 Basic Auth 绑定，必须走后端代理

use super::DownloadInfo;
use crate::config::Entry;
use regex::Regex;
use reqwest::{Client, Method};
use std::sync::OnceLock;

pub struct Webdav {
    /// scheme://host[:port]，不含路径
    origin: String,
    /// 服务器绝对根路径 = url 的路径部分 + root_path
    root: String,
    username: String,
    password: String,
    http: Client,
}

const PROPFIND_BODY: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:"><D:prop><D:displayname/><D:resourcetype/><D:getcontentlength/><D:getlastmodified/></D:prop></D:propfind>"#;

impl Webdav {
    pub fn new(url: String, username: String, password: String, root_path: String) -> Self {
        let (origin, base) = split_origin_path(&url);
        // root_path 可为 "Via" / "/Via" / "/"，统一归一后拼到 url 路径之后
        let root = join_vpath(&base, &normalize_vpath(&root_path));
        Webdav {
            origin,
            root,
            username,
            password,
            http: Client::new(),
        }
    }

    /// 对齐 Init()：PROPFIND Depth:0 校验根路径可达
    pub async fn validate(&self) -> Result<(), String> {
        if !self.origin.starts_with("http://") && !self.origin.starts_with("https://") {
            return Err("WebDAV 地址必须以 http:// 或 https:// 开头".into());
        }
        let status = self
            .propfind(&self.root, "0")
            .await
            .map_err(|e| format!("WebDAV 连接失败: {e}"))?;
        if status == reqwest::StatusCode::NOT_FOUND.as_u16() {
            return Err(format!("WebDAV 根路径不存在: {}", self.root));
        }
        if status == reqwest::StatusCode::UNAUTHORIZED.as_u16() {
            return Err("WebDAV 认证失败：用户名或密码错误".into());
        }
        if status != 207 && !(200..300).contains(&status) {
            return Err(format!("WebDAV 服务器返回异常状态码: {status}"));
        }
        Ok(())
    }

    /// fid(""/"0"/"/") -> 根；否则拼到根之后，得到服务器绝对路径
    fn resolve_abs(&self, fid: &str) -> String {
        let fid = fid.trim();
        if fid.is_empty() || fid == "0" || fid == "/" {
            self.root.clone()
        } else {
            join_vpath(&self.root, &normalize_vpath(fid))
        }
    }

    async fn propfind(&self, path: &str, depth: &str) -> Result<u16, String> {
        let url = format!("{}{}", self.origin, encode_vpath(path));
        let resp = self
            .http
            .request(Method::from_bytes(b"PROPFIND").unwrap(), &url)
            .basic_auth(&self.username, Some(&self.password))
            .header("Depth", depth)
            .header("Content-Type", "application/xml")
            .body(PROPFIND_BODY)
            .send()
            .await
            .map_err(|e| format!("PROPFIND 请求失败: {e}"))?;
        Ok(resp.status().as_u16())
    }

    pub async fn list(&self, parent_fid: &str) -> Result<Vec<Entry>, String> {
        let dir = self.resolve_abs(parent_fid);
        let resp = self
            .http
            .request(
                Method::from_bytes(b"PROPFIND").unwrap(),
                format!("{}{}", self.origin, encode_vpath(&dir)),
            )
            .basic_auth(&self.username, Some(&self.password))
            .header("Depth", "1")
            .header("Content-Type", "application/xml")
            .body(PROPFIND_BODY)
            .send()
            .await
            .map_err(|e| format!("PROPFIND 请求失败: {e}"))?;
        let status = resp.status().as_u16();
        if status == reqwest::StatusCode::UNAUTHORIZED.as_u16() {
            return Err("WebDAV 认证失败：用户名或密码错误".into());
        }
        if status == reqwest::StatusCode::NOT_FOUND.as_u16() {
            return Err(format!("WebDAV 路径不存在: {dir}"));
        }
        if status != 207 && !(200..300).contains(&status) {
            return Err(format!("WebDAV 服务器返回异常状态码: {status}"));
        }
        let body = resp
            .text()
            .await
            .map_err(|e| format!("读取响应失败: {e}"))?;

        // 自身在服务器上的绝对路径（Depth:1 的第一条是自身）
        let self_abs = dir.trim_end_matches('/').to_string();
        // root 前缀（无尾斜杠），用于把 href 绝对路径转成相对 fid
        let root_prefix = self.root.trim_end_matches('/').to_string();
        let mut out = Vec::new();
        for item in parse_multistatus(&body) {
            let path = item.path.trim_end_matches('/').to_string();
            // 跳过目录自身
            if path == self_abs || path.is_empty() {
                continue;
            }
            // href 为服务器绝对路径，转成相对配置根的 fid
            let Some(fid) = path.strip_prefix(root_prefix.as_str()) else {
                continue;
            };
            let fid = fid.trim_start_matches('/').to_string();
            if fid.is_empty() {
                continue;
            }
            let name = fid.rsplit('/').next().unwrap_or("").to_string();
            if name.is_empty() {
                continue;
            }
            out.push(Entry {
                fid,
                name,
                size: if item.is_dir { 0 } else { item.size },
                is_dir: item.is_dir,
                updated_at: item.mtime_ms,
                etag: None,
                s3_key_flag: None,
                file_type: None,
                extra: None,
            });
        }
        Ok(out)
    }

    pub async fn download(&self, e: &Entry) -> Result<DownloadInfo, String> {
        if e.is_dir {
            return Err("目录无法下载".into());
        }
        let path = self.resolve_abs(&e.fid);
        let url = format!("{}{}", self.origin, encode_vpath(&path));
        let auth = basic_auth_value(&self.username, &self.password);
        Ok(DownloadInfo {
            url,
            headers: vec![("Authorization".into(), auth)],
            proxy: true,
            local_path: None,
        })
    }

    // ---------- 写操作（对齐 Go 版 MakeDir/Move/Rename/Copy/Remove/Put） ----------

    /// 发送 MOVE / COPY 请求（Destination 头指向目标绝对路径，对齐 gowebdav）
    async fn move_or_copy(&self, method: &str, src_abs: &str, dst_abs: &str) -> Result<(), String> {
        let url = format!("{}{}", self.origin, encode_vpath(src_abs));
        let dest = format!("{}{}", self.origin, encode_vpath(dst_abs));
        let resp = self
            .http
            .request(Method::from_bytes(method.as_bytes()).unwrap(), &url)
            .basic_auth(&self.username, Some(&self.password))
            .header("Destination", &dest)
            .header("Overwrite", "T")
            .send()
            .await
            .map_err(|e| format!("{method} 请求失败: {e}"))?;
        check_dav_status(resp.status().as_u16(), method)
    }

    /// 对齐 MakeDir：MKCOL（逐级创建，对齐 gowebdav MkdirAll）
    pub async fn mkdir(&self, parent_fid: &str, name: &str) -> Result<(), String> {
        if name.is_empty() {
            return Err("目录名为空".into());
        }
        let base = self.resolve_abs(parent_fid);
        // MkdirAll：逐级 MKCOL（已存在视为成功）
        let mut cur = base;
        for seg in normalize_vpath(name).split('/').filter(|s| !s.is_empty()) {
            cur = join_vpath(&cur, &format!("/{seg}"));
            let url = format!("{}{}", self.origin, encode_vpath(&cur));
            let resp = self
                .http
                .request(Method::from_bytes(b"MKCOL").unwrap(), &url)
                .basic_auth(&self.username, Some(&self.password))
                .send()
                .await
                .map_err(|e| format!("MKCOL 请求失败: {e}"))?;
            let status = resp.status().as_u16();
            // 405 = 已存在（MkdirAll 语义：容忍），201 = 创建成功
            if status != 405 && status != 201 && !(200..300).contains(&status) {
                return Err(format!("MKCOL {cur} 返回 {status}"));
            }
        }
        Ok(())
    }

    /// 对齐 Move：MOVE src -> dstDir/name（Overwrite: T）
    pub async fn move_entry(
        &self,
        _parent_fid: &str,
        e: &Entry,
        dst_dir_fid: &str,
    ) -> Result<(), String> {
        let src = self.resolve_abs(&e.fid);
        let dst_dir = self.resolve_abs(dst_dir_fid);
        let dst = join_vpath(&dst_dir, &format!("/{}", encode_vpath(&e.name)));
        self.move_or_copy("MOVE", &src, &dst).await
    }

    /// 对齐 Rename：MOVE 同目录改名
    pub async fn rename(&self, _parent_fid: &str, e: &Entry, new_name: &str) -> Result<(), String> {
        if new_name.contains('/') {
            return Err("名称不能包含 /".into());
        }
        let src = self.resolve_abs(&e.fid);
        // 同目录：src 去掉末段 + 新名（对齐 path.Join(path.Dir(srcObj.GetPath()), newName)）
        let parent = match src.rfind('/') {
            Some(i) => src[..i].to_string(),
            None => String::new(),
        };
        let dst = if parent.is_empty() {
            format!("/{}", encode_vpath(new_name))
        } else {
            join_vpath(&parent, &format!("/{}", encode_vpath(new_name)))
        };
        self.move_or_copy("MOVE", &src, &dst).await
    }

    /// 对齐 Copy：COPY src -> dstDir/name（Overwrite: T）
    pub async fn copy(
        &self,
        _parent_fid: &str,
        e: &Entry,
        dst_dir_fid: &str,
    ) -> Result<(), String> {
        let src = self.resolve_abs(&e.fid);
        let dst_dir = self.resolve_abs(dst_dir_fid);
        let dst = join_vpath(&dst_dir, &format!("/{}", encode_vpath(&e.name)));
        self.move_or_copy("COPY", &src, &dst).await
    }

    /// 对齐 Remove：DELETE（RemoveAll 语义，对齐 gowebdav RemoveAll）
    pub async fn remove(&self, _parent_fid: &str, e: &Entry) -> Result<(), String> {
        let path = self.resolve_abs(&e.fid);
        let url = format!("{}{}", self.origin, encode_vpath(&path));
        let resp = self
            .http
            .delete(&url)
            .basic_auth(&self.username, Some(&self.password))
            .send()
            .await
            .map_err(|e| format!("DELETE 请求失败: {e}"))?;
        let status = resp.status().as_u16();
        // 404 视为已删除（RemoveAll 幂等语义）
        if status == 404 || status == 200 || status == 204 {
            return Ok(());
        }
        Err(format!("DELETE 返回 {status}"))
    }

    /// 对齐 Put：PUT 流式上传（Content-Type 按扩展名推断；
    /// 不手设 Content-Length，reqwest 对流式 body 走 chunked，避免与实际字节数冲突）
    pub async fn put(&self, dst_dir_fid: &str, input: super::PutInput) -> Result<(), String> {
        use tokio_util::io::ReaderStream;
        let dst_dir = self.resolve_abs(dst_dir_fid);
        let dst = join_vpath(&dst_dir, &format!("/{}", encode_vpath(&input.name)));
        let url = format!("{}{}", self.origin, encode_vpath(&dst));
        let mimetype = mime_by_ext(&input.name);
        let resp = self
            .http
            .put(&url)
            .basic_auth(&self.username, Some(&self.password))
            .header("Content-Type", mimetype)
            .body(reqwest::Body::wrap_stream(ReaderStream::with_capacity(
                input.reader,
                64 * 1024,
            )))
            .send()
            .await
            .map_err(|e| format!("PUT 请求失败: {e}"))?;
        check_dav_status(resp.status().as_u16(), "PUT")
    }
}

/// WebDAV 写操作状态码检查：2xx 视为成功
fn check_dav_status(status: u16, op: &str) -> Result<(), String> {
    if (200..300).contains(&status) {
        Ok(())
    } else if status == 401 {
        Err("WebDAV 认证失败：用户名或密码错误".into())
    } else {
        Err(format!("{op} 返回 {status}"))
    }
}

/// 扩展名 -> MIME（对齐 Go utils.GetMimeType 的常用集）
fn mime_by_ext(name: &str) -> &'static str {
    let ext = name.rsplit('.').next().unwrap_or("").to_lowercase();
    match ext.as_str() {
        "txt" | "md" | "log" => "text/plain; charset=utf-8",
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css",
        "js" => "application/javascript",
        "json" => "application/json",
        "xml" => "application/xml",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "gz" => "application/gzip",
        "tar" => "application/x-tar",
        "mp4" | "m4v" => "video/mp4",
        "mkv" => "video/x-matroska",
        "webm" => "video/webm",
        "avi" => "video/x-msvideo",
        "mov" => "video/quicktime",
        "flv" => "video/x-flv",
        "ts" => "video/mp2t",
        "mp3" => "audio/mpeg",
        "flac" => "audio/flac",
        "ogg" | "opus" => "audio/ogg",
        "m4a" => "audio/mp4",
        "wav" => "audio/wav",
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        _ => "application/octet-stream",
    }
}

// ---------- 路径工具 ----------

/// 拆分 url 为 (origin, 路径部分)："http://h:5244/dav" -> ("http://h:5244", "/dav")
fn split_origin_path(url: &str) -> (String, String) {
    let t = url.trim().trim_end_matches('/');
    let scheme_end = t.find("://").map(|i| i + 3).unwrap_or(0);
    match t[scheme_end..].find('/') {
        Some(p) => {
            let idx = scheme_end + p;
            (t[..idx].to_string(), t[idx..].to_string())
        }
        None => (t.to_string(), String::new()),
    }
}

/// 拼接服务器绝对路径：base 无尾斜杠，p 以 / 开头
fn join_vpath(base: &str, p: &str) -> String {
    if base.is_empty() || base == "/" {
        return normalize_vpath(p);
    }
    if p == "/" || p.is_empty() {
        return base.to_string();
    }
    format!("{base}{p}")
}

/// 归一化虚拟路径：确保以 / 开头、不以 / 结尾
fn normalize_vpath(p: &str) -> String {
    let mut s = p.trim().to_string();
    if !s.starts_with('/') {
        s.insert(0, '/');
    }
    while s.len() > 1 && s.ends_with('/') {
        s.pop();
    }
    if s.is_empty() {
        "/".to_string()
    } else {
        s
    }
}

/// 按段百分号编码（保留 /）
fn encode_vpath(p: &str) -> String {
    p.split('/')
        .map(|seg| {
            let mut out = String::new();
            for b in seg.bytes() {
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

fn basic_auth_value(user: &str, pass: &str) -> String {
    use base64::Engine;
    let raw = format!("{user}:{pass}");
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(raw.as_bytes())
    )
}

// ---------- multistatus XML 容错解析 ----------

struct DavItem {
    path: String,
    is_dir: bool,
    size: u64,
    mtime_ms: Option<i64>,
}

/// 命名空间前缀各异（D:/d:/无），用容错正则抽取
fn res(pat: &'static str) -> &'static Regex {
    static LOCK: OnceLock<std::collections::HashMap<&'static str, Regex>> = OnceLock::new();
    LOCK.get_or_init(|| {
        let mut m = std::collections::HashMap::new();
        m.insert(
            "resp",
            Regex::new(r"(?is)<(\w+:)?response\b[^>]*>(.*?)</(\w+:)?response>").unwrap(),
        );
        m.insert(
            "href",
            Regex::new(r"(?is)<(\w+:)?href[^>]*>(.*?)</(\w+:)?href>").unwrap(),
        );
        m.insert(
            "collection",
            Regex::new(r"(?is)<(\w+:)?resourcetype[^>]*>\s*<(\w+:)?collection\b").unwrap(),
        );
        m.insert(
            "len",
            Regex::new(r"(?is)<(\w+:)?getcontentlength[^>]*>\s*(\d+)").unwrap(),
        );
        m.insert(
            "lm",
            Regex::new(r"(?is)<(\w+:)?getlastmodified[^>]*>\s*([^<]+?)\s*<").unwrap(),
        );
        m
    })
    .get(pat)
    .unwrap()
}

/// 去掉 CDATA 包装并反转义基本 XML 实体
fn xml_text(raw: &str) -> String {
    let s = raw.trim();
    let s = s
        .strip_prefix("<![CDATA[")
        .and_then(|r| r.strip_suffix("]]>"))
        .unwrap_or(s);
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let h = u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 2]).unwrap_or(""), 16);
            let l = u8::from_str_radix(std::str::from_utf8(&b[i + 2..i + 3]).unwrap_or(""), 16);
            if let (Ok(h), Ok(l)) = (h, l) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
            out.push(b[i]);
            i += 1;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

/// 从 href 提取路径：去掉 scheme://host 前缀并解码
fn href_to_path(href: &str) -> String {
    let t = xml_text(href);
    let t = if let Some(idx) = t.find("://") {
        let rest = &t[idx + 3..];
        match rest.find('/') {
            Some(p) => rest[p..].to_string(),
            None => "/".to_string(),
        }
    } else {
        t
    };
    normalize_vpath(&percent_decode(&t))
}

fn parse_multistatus(body: &str) -> Vec<DavItem> {
    let mut out = Vec::new();
    for cap in res("resp").captures_iter(body) {
        let block = cap.get(2).map(|m| m.as_str()).unwrap_or("");
        let Some(href_cap) = res("href").captures(block) else {
            continue;
        };
        let path = href_to_path(href_cap.get(2).map(|m| m.as_str()).unwrap_or(""));
        if path.is_empty() {
            continue;
        }
        let is_dir = res("collection").is_match(block) || path.ends_with('/');
        let size = res("len")
            .captures(block)
            .and_then(|c| c.get(2))
            .and_then(|m| m.as_str().parse().ok())
            .unwrap_or(0);
        let mtime_ms = res("lm")
            .captures(block)
            .and_then(|c| c.get(2))
            .map(|m| m.as_str().trim().to_string())
            .and_then(|s| parse_http_date_ms(&s));
        out.push(DavItem {
            path,
            is_dir,
            size,
            mtime_ms,
        });
    }
    out
}

/// 解析 RFC1123 "Mon, 02 Jan 2006 15:04:05 GMT"（也容忍 asctime 格式）
fn parse_http_date_ms(s: &str) -> Option<i64> {
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() < 5 {
        return None;
    }
    let (day, mon, year, time) = if parts[0].ends_with(',') {
        (
            parts[1].parse::<i64>().ok()?,
            month_of(parts[2])?,
            parts[3].parse::<i64>().ok()?,
            parts[4],
        )
    } else {
        // asctime: "Sun Nov  6 08:49:37 1994"
        (
            parts[2].parse::<i64>().ok()?,
            month_of(parts[1])?,
            parts[4].parse::<i64>().ok()?,
            parts[3],
        )
    };
    let tp: Vec<&str> = time.split(':').collect();
    if tp.len() < 3 {
        return None;
    }
    let h = tp[0].parse::<i64>().ok()?;
    let mi = tp[1].parse::<i64>().ok()?;
    let sec = tp[2].parse::<i64>().ok()?;
    let days = days_from_civil(year, mon, day);
    Some((days * 86_400 + h * 3600 + mi * 60 + sec) * 1000)
}

fn month_of(s: &str) -> Option<i64> {
    let pfx: String = s.chars().take(3).collect::<String>().to_lowercase();
    match pfx.as_str() {
        "jan" => Some(1),
        "feb" => Some(2),
        "mar" => Some(3),
        "apr" => Some(4),
        "may" => Some(5),
        "jun" => Some(6),
        "jul" => Some(7),
        "aug" => Some(8),
        "sep" => Some(9),
        "oct" => Some(10),
        "nov" => Some(11),
        "dec" => Some(12),
        _ => None,
    }
}

/// Howard Hinnant days_from_civil
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_vpath() {
        assert_eq!(normalize_vpath("/a/b/"), "/a/b");
        assert_eq!(normalize_vpath("a"), "/a");
        assert_eq!(normalize_vpath("/"), "/");
    }

    #[test]
    fn test_split_origin_path() {
        assert_eq!(
            split_origin_path("http://h:5244/dav"),
            ("http://h:5244".into(), "/dav".into())
        );
        assert_eq!(
            split_origin_path("http://h:5244"),
            ("http://h:5244".into(), "".into())
        );
        assert_eq!(
            split_origin_path("http://h:5244/"),
            ("http://h:5244".into(), "".into())
        );
    }

    #[test]
    fn test_join_vpath() {
        assert_eq!(join_vpath("/dav", "/Via"), "/dav/Via");
        assert_eq!(join_vpath("", "/Via"), "/Via");
        assert_eq!(join_vpath("/dav", "/"), "/dav");
        assert_eq!(join_vpath("/", "/Via"), "/Via");
    }

    #[test]
    fn test_webdav_root_resolution() {
        // url 带路径 + root_path 带名称
        let d = Webdav::new(
            "http://h:5244/dav".into(),
            "u".into(),
            "p".into(),
            "Via".into(),
        );
        assert_eq!(d.root, "/dav/Via");
        assert_eq!(d.resolve_abs(""), "/dav/Via");
        assert_eq!(d.resolve_abs("0"), "/dav/Via");
        assert_eq!(d.resolve_abs("/"), "/dav/Via");
        assert_eq!(d.resolve_abs("/sub/f.txt"), "/dav/Via/sub/f.txt");
        // url 不带路径 + root_path 为根
        let d2 = Webdav::new("http://h:5244".into(), "u".into(), "p".into(), "/".into());
        assert_eq!(d2.root, "/");
        assert_eq!(d2.resolve_abs("/x"), "/x");
    }

    #[test]
    fn test_list_fids_relative_to_root() {
        let d = Webdav::new(
            "http://h:5244/dav".into(),
            "u".into(),
            "p".into(),
            "".into(),
        );
        let body = r#"<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>/dav/</D:href>
    <D:propstat><D:prop><D:resourcetype><D:collection/></D:resourcetype></D:prop></D:propstat>
  </D:response>
  <D:response>
    <D:href>/dav/Via/</D:href>
    <D:propstat><D:prop><D:resourcetype><D:collection/></D:resourcetype></D:prop></D:propstat>
  </D:response>
  <D:response>
    <D:href>/dav/dj.txt</D:href>
    <D:propstat><D:prop><D:resourcetype/><D:getcontentlength>2</D:getcontentlength></D:prop></D:propstat>
  </D:response>
</D:multistatus>"#;
        let items = parse_multistatus(body);
        // 模拟 list() 的 fid 转换逻辑
        let root_prefix = d.root.trim_end_matches('/');
        let fids: Vec<String> = items
            .iter()
            .filter_map(|it| {
                let p = it.path.trim_end_matches('/');
                if p == d.root.trim_end_matches('/') || p.is_empty() {
                    return None;
                }
                let fid = p.strip_prefix(root_prefix)?.trim_start_matches('/');
                if fid.is_empty() {
                    None
                } else {
                    Some(fid.to_string())
                }
            })
            .collect();
        assert_eq!(fids, vec!["Via", "dj.txt"]);
    }

    #[test]
    fn test_encode_vpath() {
        assert_eq!(encode_vpath("/a b/中.txt"), "/a%20b/%E4%B8%AD.txt");
        assert_eq!(encode_vpath("/x+y/z"), "/x%2By/z");
    }

    #[test]
    fn test_parse_multistatus() {
        let body = r#"<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>/</D:href>
    <D:propstat><D:prop><D:resourcetype><D:collection/></D:resourcetype></D:prop></D:propstat>
  </D:response>
  <D:response>
    <D:href>/dir%20one/</D:href>
    <D:propstat><D:prop>
      <D:resourcetype><D:collection/></D:resourcetype>
      <D:getlastmodified>Tue, 15 Nov 2094 12:45:26 GMT</D:getlastmodified>
    </D:prop></D:propstat>
  </D:response>
  <D:response>
    <D:href>/dir%20one/a%2Bb.txt</D:href>
    <D:propstat><D:prop>
      <D:resourcetype/>
      <D:getcontentlength>1234</D:getcontentlength>
      <D:getlastmodified>Mon, 01 Jan 2024 00:00:00 GMT</D:getlastmodified>
    </D:prop></D:propstat>
  </D:response>
</D:multistatus>"#;
        let items = parse_multistatus(body);
        assert_eq!(items.len(), 3);
        assert!(items[0].is_dir);
        assert_eq!(items[1].path, "/dir one");
        assert!(items[1].is_dir);
        assert_eq!(items[2].path, "/dir one/a+b.txt");
        assert!(!items[2].is_dir);
        assert_eq!(items[2].size, 1234);
        assert_eq!(items[2].mtime_ms, Some(1_704_067_200_000));
    }

    #[test]
    fn test_percent_decode() {
        assert_eq!(percent_decode("a%20b"), "a b");
        assert_eq!(percent_decode("%E4%B8%AD"), "中");
        assert_eq!(percent_decode("a%zz"), "a%zz");
    }

    #[test]
    fn test_http_date() {
        assert_eq!(
            parse_http_date_ms("Mon, 01 Jan 2024 00:00:00 GMT"),
            Some(1_704_067_200_000)
        );
    }
}
