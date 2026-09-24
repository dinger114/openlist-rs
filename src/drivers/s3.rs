//! S3 兼容存储驱动（对齐 Go 版 drivers/s3）
//!
//! - fid 为对象路径（以 / 开头或相对 root_path），目录以「前缀 + /」表示
//! - list：ListObjectsV2 + Delimiter=/
//! - download：预签名 GET URL（默认 4 小时），可直连
//! - 写操作：PutObject / DeleteObject / CopyObject / 目录占位对象

use super::{DownloadInfo, PutInput};
use crate::config::Entry;
use hmac::{Hmac, Mac};
use reqwest::Client;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

pub struct S3 {
    bucket: String,
    endpoint: String,
    region: String,
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
    custom_host: String,
    force_path_style: bool,
    sign_url_expire_hours: u64,
    root_path: String,
    http: Client,
}

impl S3 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bucket: String,
        endpoint: String,
        region: String,
        access_key_id: String,
        secret_access_key: String,
        session_token: String,
        custom_host: String,
        force_path_style: bool,
        sign_url_expire_hours: u64,
        root_path: String,
    ) -> Self {
        let region = if region.trim().is_empty() {
            "us-east-1".into()
        } else {
            region
        };
        let mut endpoint = endpoint.trim().trim_end_matches('/').to_string();
        if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
            endpoint = format!("https://{endpoint}");
        }
        let root_path = normalize_key_prefix(&root_path);
        S3 {
            bucket,
            endpoint,
            region,
            access_key_id,
            secret_access_key,
            session_token,
            custom_host: custom_host.trim().trim_end_matches('/').to_string(),
            force_path_style,
            sign_url_expire_hours: if sign_url_expire_hours == 0 {
                4
            } else {
                sign_url_expire_hours
            },
            root_path,
            http: Client::new(),
        }
    }

    pub async fn validate(&self) -> Result<(), String> {
        // ListObjectsV2 max-keys=1 探测连通性
        let prefix = self.root_path.clone();
        let qs = format!(
            "list-type=2&max-keys=1&prefix={}",
            urlencoding_encode(&prefix)
        );
        let (status, body) = self
            .signed_request("GET", "", &qs, b"", "application/xml")
            .await?;
        if status == 403 || status == 401 {
            return Err(format!("S3 认证失败 ({status}): {}", truncate(&body, 200)));
        }
        if status == 404 {
            return Err(format!("S3 Bucket 不存在或不在该区域: {}", self.bucket));
        }
        if !(200..300).contains(&status) {
            return Err(format!("S3 连接失败 ({status}): {}", truncate(&body, 300)));
        }
        Ok(())
    }

    fn resolve_key(&self, fid: &str) -> String {
        let fid = fid.trim();
        if fid.is_empty() || fid == "0" || fid == "/" {
            return self.root_path.clone();
        }
        let rel = fid.trim_start_matches('/');
        if self.root_path.is_empty() {
            rel.to_string()
        } else {
            format!(
                "{}{}",
                self.root_path.trim_end_matches('/'),
                if rel.is_empty() {
                    String::new()
                } else {
                    format!("/{rel}")
                }
            )
            .trim_start_matches('/')
            .to_string()
        }
    }

    /// fid 相对 root 的路径（用于 Entry.fid）
    fn key_to_fid(&self, key: &str) -> String {
        let key = key.trim_start_matches('/');
        let root = self.root_path.trim_start_matches('/').trim_end_matches('/');
        if root.is_empty() {
            format!("/{key}")
        } else if let Some(rest) = key.strip_prefix(root) {
            let rest = rest.trim_start_matches('/');
            if rest.is_empty() {
                "/".into()
            } else {
                format!("/{rest}")
            }
        } else {
            format!("/{key}")
        }
    }

    pub async fn list(&self, parent_fid: &str) -> Result<Vec<Entry>, String> {
        let mut prefix = self.resolve_key(parent_fid);
        if !prefix.is_empty() && !prefix.ends_with('/') {
            prefix.push('/');
        }
        let mut out = Vec::new();
        let mut continuation: Option<String> = None;
        loop {
            let mut qs = format!(
                "list-type=2&delimiter=%2F&prefix={}",
                urlencoding_encode(&prefix)
            );
            if let Some(ref token) = continuation {
                qs.push_str(&format!(
                    "&continuation-token={}",
                    urlencoding_encode(token)
                ));
            }
            let (status, body) = self
                .signed_request("GET", "", &qs, b"", "application/xml")
                .await?;
            if !(200..300).contains(&status) {
                return Err(format!(
                    "S3 ListObjects 失败 ({status}): {}",
                    truncate(&body, 400)
                ));
            }
            // 解析 CommonPrefixes + Contents（容错正则）
            for p in extract_xml_tags(&body, "Prefix") {
                let name = p
                    .trim_end_matches('/')
                    .rsplit('/')
                    .next()
                    .unwrap_or("")
                    .to_string();
                if name.is_empty() {
                    continue;
                }
                // 跳过当前前缀自身
                if p == prefix {
                    continue;
                }
                let fid = self.key_to_fid(p.trim_end_matches('/'));
                out.push(Entry {
                    fid,
                    name,
                    size: 0,
                    is_dir: true,
                    updated_at: None,
                    etag: None,
                    s3_key_flag: None,
                    file_type: None,
                    extra: None,
                });
            }
            // Contents: Key / Size / LastModified
            for obj in extract_xml_blocks(&body, "Contents") {
                let key = extract_xml_tag(&obj, "Key").unwrap_or_default();
                if key.is_empty() || key.ends_with('/') {
                    continue;
                }
                // 跳过占位文件
                let name = key.rsplit('/').next().unwrap_or("").to_string();
                if name.is_empty() || name == ".openlistkeep" || name == ".alistkeep" {
                    continue;
                }
                let size: u64 = extract_xml_tag(&obj, "Size")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                let updated_at =
                    extract_xml_tag(&obj, "LastModified").and_then(|s| parse_rfc3339_ms(&s));
                let fid = self.key_to_fid(&key);
                out.push(Entry {
                    fid,
                    name,
                    size,
                    is_dir: false,
                    updated_at,
                    etag: extract_xml_tag(&obj, "ETag").map(|e| e.trim_matches('"').to_string()),
                    s3_key_flag: None,
                    file_type: None,
                    extra: None,
                });
            }
            let truncated = extract_xml_tag(&body, "IsTruncated")
                .map(|s| s.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            if !truncated {
                break;
            }
            continuation = extract_xml_tag(&body, "NextContinuationToken");
            if continuation.is_none() {
                break;
            }
        }
        Ok(out)
    }

    pub async fn download(&self, e: &Entry) -> Result<DownloadInfo, String> {
        if e.is_dir {
            return Err("目录无法下载".into());
        }
        let key = self.resolve_key(&e.fid);
        let url = self.presign_get(&key)?;
        Ok(DownloadInfo {
            url,
            headers: vec![],
            proxy: false,
            local_path: None,
        })
    }

    pub async fn mkdir(&self, parent_fid: &str, name: &str) -> Result<(), String> {
        if name.is_empty() {
            return Err("目录名为空".into());
        }
        let parent = self.resolve_key(parent_fid);
        let key = if parent.is_empty() {
            format!("{}/.openlistkeep", name.trim_matches('/'))
        } else {
            format!(
                "{}/{}/.openlistkeep",
                parent.trim_end_matches('/'),
                name.trim_matches('/')
            )
        };
        let (status, body) = self
            .signed_request("PUT", &key, "", b"", "application/octet-stream")
            .await?;
        if !(200..300).contains(&status) {
            return Err(format!(
                "S3 创建目录失败 ({status}): {}",
                truncate(&body, 200)
            ));
        }
        Ok(())
    }

    pub async fn rename(&self, _parent_fid: &str, e: &Entry, new_name: &str) -> Result<(), String> {
        if new_name.contains('/') {
            return Err("名称不能包含 /".into());
        }
        let src = self.resolve_key(&e.fid);
        let parent = match src.rfind('/') {
            Some(i) => src[..i].to_string(),
            None => String::new(),
        };
        let dst = if parent.is_empty() {
            new_name.to_string()
        } else {
            format!("{parent}/{new_name}")
        };
        if e.is_dir {
            return Err("S3 目录重命名请使用移动（暂不支持递归重命名）".into());
        }
        self.copy_object(&src, &dst).await?;
        self.delete_object(&src).await
    }

    pub async fn move_entry(
        &self,
        _parent_fid: &str,
        e: &Entry,
        dst_dir_fid: &str,
    ) -> Result<(), String> {
        let src = self.resolve_key(&e.fid);
        let dst_dir = self.resolve_key(dst_dir_fid);
        let name = e.name.as_str();
        let dst = if dst_dir.is_empty() {
            name.to_string()
        } else {
            format!("{}/{name}", dst_dir.trim_end_matches('/'))
        };
        if e.is_dir {
            return Err("S3 目录移动暂不支持递归".into());
        }
        self.copy_object(&src, &dst).await?;
        self.delete_object(&src).await
    }

    pub async fn copy(
        &self,
        _parent_fid: &str,
        e: &Entry,
        dst_dir_fid: &str,
    ) -> Result<(), String> {
        if e.is_dir {
            return Err("S3 目录复制暂不支持递归".into());
        }
        let src = self.resolve_key(&e.fid);
        let dst_dir = self.resolve_key(dst_dir_fid);
        let dst = if dst_dir.is_empty() {
            e.name.clone()
        } else {
            format!("{}/{}", dst_dir.trim_end_matches('/'), e.name)
        };
        self.copy_object(&src, &dst).await
    }

    pub async fn remove(&self, _parent_fid: &str, e: &Entry) -> Result<(), String> {
        if e.is_dir {
            // 列出并删除前缀下所有对象（简单实现）
            let mut prefix = self.resolve_key(&e.fid);
            if !prefix.is_empty() && !prefix.ends_with('/') {
                prefix.push('/');
            }
            let mut continuation: Option<String> = None;
            loop {
                let mut qs = format!("list-type=2&prefix={}", urlencoding_encode(&prefix));
                if let Some(ref t) = continuation {
                    qs.push_str(&format!("&continuation-token={}", urlencoding_encode(t)));
                }
                let (status, body) = self
                    .signed_request("GET", "", &qs, b"", "application/xml")
                    .await?;
                if !(200..300).contains(&status) {
                    return Err(format!("S3 列举删除失败 ({status})"));
                }
                for obj in extract_xml_blocks(&body, "Contents") {
                    if let Some(key) = extract_xml_tag(&obj, "Key") {
                        self.delete_object(&key).await?;
                    }
                }
                let truncated = extract_xml_tag(&body, "IsTruncated")
                    .map(|s| s.eq_ignore_ascii_case("true"))
                    .unwrap_or(false);
                if !truncated {
                    break;
                }
                continuation = extract_xml_tag(&body, "NextContinuationToken");
                if continuation.is_none() {
                    break;
                }
            }
            Ok(())
        } else {
            let key = self.resolve_key(&e.fid);
            self.delete_object(&key).await
        }
    }

    pub async fn put(&self, dst_dir_fid: &str, input: PutInput) -> Result<(), String> {
        let dir = self.resolve_key(dst_dir_fid);
        let key = if dir.is_empty() {
            input.name.clone()
        } else {
            format!("{}/{}", dir.trim_end_matches('/'), input.name)
        };
        // 将流读入内存（对齐简化实现；大文件可后续改 multipart）
        let mut reader = input.reader;
        let mut buf = Vec::with_capacity(input.size.min(64 * 1024 * 1024) as usize);
        let mut tmp = [0u8; 64 * 1024];
        loop {
            use tokio::io::AsyncReadExt;
            let n = reader
                .read(&mut tmp)
                .await
                .map_err(|e| format!("读取上传内容失败: {e}"))?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.len() > 200 * 1024 * 1024 {
                return Err("单文件上传暂限 200MB，请使用分片上传客户端".into());
            }
        }
        let (status, body) = self
            .signed_request("PUT", &key, "", &buf, "application/octet-stream")
            .await?;
        if !(200..300).contains(&status) {
            return Err(format!("S3 上传失败 ({status}): {}", truncate(&body, 200)));
        }
        Ok(())
    }

    // ---------- 内部 HTTP + SigV4 ----------

    fn host_and_path(&self, key: &str) -> (String, String) {
        let ep = url::Url::parse(&self.endpoint).ok();
        let host = ep
            .as_ref()
            .and_then(|u| u.host_str())
            .unwrap_or("")
            .to_string();
        let port = ep.as_ref().and_then(|u| u.port());
        let host_header = match port {
            Some(p) if p != 80 && p != 443 => format!("{host}:{p}"),
            _ => host.clone(),
        };
        if self.force_path_style {
            let path = if key.is_empty() {
                format!("/{}/", self.bucket)
            } else {
                format!("/{}/{}", self.bucket, key)
            };
            (host_header, path)
        } else {
            // virtual-hosted
            let path = if key.is_empty() {
                "/".into()
            } else {
                format!("/{key}")
            };
            (format!("{}.{}", self.bucket, host_header), path)
        }
    }

    fn object_url(&self, key: &str) -> String {
        let (host, path) = self.host_and_path(key);
        let scheme = if self.endpoint.starts_with("http://") {
            "http"
        } else {
            "https"
        };
        // path-style URL 用 endpoint 原 host
        if self.force_path_style {
            let base = self.endpoint.trim_end_matches('/');
            format!("{base}{path}")
        } else {
            format!("{scheme}://{host}{path}")
        }
    }

    async fn signed_request(
        &self,
        method: &str,
        key: &str,
        query: &str,
        body: &[u8],
        content_type: &str,
    ) -> Result<(u16, String), String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let amz_date = epoch_to_amz_date(now);
        let date_stamp = &amz_date[..8];
        let payload_hash = hex_sha256(body);
        let (host, canonical_uri) = self.host_and_path(key);
        let canonical_querystring = canonicalize_query(query);
        let mut headers = vec![
            ("content-type".to_string(), content_type.to_string()),
            ("host".to_string(), host.clone()),
            ("x-amz-content-sha256".to_string(), payload_hash.clone()),
            ("x-amz-date".to_string(), amz_date.clone()),
        ];
        if !self.session_token.is_empty() {
            headers.push((
                "x-amz-security-token".to_string(),
                self.session_token.clone(),
            ));
        }
        headers.sort_by(|a, b| a.0.cmp(&b.0));
        let signed_headers: String = headers
            .iter()
            .map(|(k, _)| k.as_str())
            .collect::<Vec<_>>()
            .join(";");
        let canonical_headers: String = headers
            .iter()
            .map(|(k, v)| format!("{k}:{}\n", v.trim()))
            .collect();
        let canonical_request = format!(
            "{method}\n{canonical_uri}\n{canonical_querystring}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
        );
        let credential_scope = format!("{date_stamp}/{}/s3/aws4_request", self.region);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{}",
            hex_sha256(canonical_request.as_bytes())
        );
        let signing_key =
            get_signature_key(&self.secret_access_key, date_stamp, &self.region, "s3");
        let signature = hex_hmac(&signing_key, string_to_sign.as_bytes());
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
            self.access_key_id
        );

        let mut url = self.object_url(key);
        if !canonical_querystring.is_empty() {
            url.push('?');
            url.push_str(&canonical_querystring);
        }
        let mut req = match method {
            "GET" => self.http.get(&url),
            "PUT" => self.http.put(&url),
            "DELETE" => self.http.delete(&url),
            "HEAD" => self.http.head(&url),
            _ => self.http.request(
                reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::GET),
                &url,
            ),
        };
        for (k, v) in &headers {
            if k == "host" {
                continue; // reqwest 自动设置
            }
            req = req.header(k.as_str(), v.as_str());
        }
        req = req.header("Authorization", &authorization);
        if method == "PUT" || method == "POST" {
            req = req.body(body.to_vec());
        }
        let resp = req.send().await.map_err(|e| format!("S3 请求失败: {e}"))?;
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        Ok((status, text))
    }

    async fn delete_object(&self, key: &str) -> Result<(), String> {
        let (status, body) = self
            .signed_request("DELETE", key, "", b"", "application/xml")
            .await?;
        if status == 404 || (200..300).contains(&status) {
            Ok(())
        } else {
            Err(format!("S3 删除失败 ({status}): {}", truncate(&body, 200)))
        }
    }

    async fn copy_object(&self, src_key: &str, dst_key: &str) -> Result<(), String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let amz_date = epoch_to_amz_date(now);
        let date_stamp = &amz_date[..8];
        let payload_hash = hex_sha256(b"");
        let (host, canonical_uri) = self.host_and_path(dst_key);
        let copy_source = format!("{}/{}", self.bucket, src_key);
        let mut headers = vec![
            ("host".to_string(), host.clone()),
            ("x-amz-content-sha256".to_string(), payload_hash.clone()),
            ("x-amz-copy-source".to_string(), copy_source),
            ("x-amz-date".to_string(), amz_date.clone()),
        ];
        if !self.session_token.is_empty() {
            headers.push((
                "x-amz-security-token".to_string(),
                self.session_token.clone(),
            ));
        }
        headers.sort_by(|a, b| a.0.cmp(&b.0));
        let signed_headers: String = headers
            .iter()
            .map(|(k, _)| k.as_str())
            .collect::<Vec<_>>()
            .join(";");
        let canonical_headers: String = headers
            .iter()
            .map(|(k, v)| format!("{k}:{}\n", v.trim()))
            .collect();
        let canonical_request = format!(
            "PUT\n{canonical_uri}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
        );
        let credential_scope = format!("{date_stamp}/{}/s3/aws4_request", self.region);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{}",
            hex_sha256(canonical_request.as_bytes())
        );
        let signing_key =
            get_signature_key(&self.secret_access_key, date_stamp, &self.region, "s3");
        let signature = hex_hmac(&signing_key, string_to_sign.as_bytes());
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
            self.access_key_id
        );
        let url = self.object_url(dst_key);
        let mut req = self.http.put(&url);
        for (k, v) in &headers {
            if k == "host" {
                continue;
            }
            req = req.header(k.as_str(), v.as_str());
        }
        req = req.header("Authorization", &authorization);
        let resp = req.send().await.map_err(|e| format!("S3 Copy 失败: {e}"))?;
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        if !(200..300).contains(&status) {
            return Err(format!("S3 Copy 失败 ({status}): {}", truncate(&body, 200)));
        }
        Ok(())
    }

    fn presign_get(&self, key: &str) -> Result<String, String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let amz_date = epoch_to_amz_date(now);
        let date_stamp = &amz_date[..8];
        let expires = self.sign_url_expire_hours * 3600;
        let credential_scope = format!("{date_stamp}/{}/s3/aws4_request", self.region);
        let credential = format!("{}/{}", self.access_key_id, credential_scope);

        let (host, canonical_uri) = if !self.custom_host.is_empty() {
            // 自定义域名：按 path 拼接
            let ch = self.custom_host.trim();
            let (scheme_host, path_prefix) =
                if ch.starts_with("http://") || ch.starts_with("https://") {
                    let u = url::Url::parse(ch).map_err(|e| e.to_string())?;
                    let h = match u.port() {
                        Some(p) => format!("{}:{p}", u.host_str().unwrap_or("")),
                        None => u.host_str().unwrap_or("").to_string(),
                    };
                    let scheme = u.scheme().to_string();
                    (
                        format!("{scheme}://{h}"),
                        u.path().trim_end_matches('/').to_string(),
                    )
                } else {
                    (format!("https://{ch}"), String::new())
                };
            let path = if key.is_empty() {
                format!("{path_prefix}/")
            } else {
                format!("{path_prefix}/{key}")
            };
            // host for signing
            let host_only = scheme_host
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .to_string();
            let _ = scheme_host;
            (host_only, if path.is_empty() { "/".into() } else { path })
        } else {
            self.host_and_path(key)
        };

        let mut qs_parts = vec![
            "X-Amz-Algorithm=AWS4-HMAC-SHA256".to_string(),
            format!("X-Amz-Credential={}", urlencoding_encode(&credential)),
            format!("X-Amz-Date={amz_date}"),
            format!("X-Amz-Expires={expires}"),
            "X-Amz-SignedHeaders=host".to_string(),
        ];
        if !self.session_token.is_empty() {
            qs_parts.push(format!(
                "X-Amz-Security-Token={}",
                urlencoding_encode(&self.session_token)
            ));
        }
        qs_parts.sort();
        let canonical_querystring = qs_parts.join("&");
        let canonical_headers = format!("host:{host}\n");
        let payload_hash = "UNSIGNED-PAYLOAD";
        let canonical_request = format!(
            "GET\n{canonical_uri}\n{canonical_querystring}\n{canonical_headers}\nhost\n{payload_hash}"
        );
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{}",
            hex_sha256(canonical_request.as_bytes())
        );
        let signing_key =
            get_signature_key(&self.secret_access_key, date_stamp, &self.region, "s3");
        let signature = hex_hmac(&signing_key, string_to_sign.as_bytes());

        let base = if !self.custom_host.is_empty() {
            let ch = self.custom_host.trim().trim_end_matches('/');
            if ch.starts_with("http://") || ch.starts_with("https://") {
                ch.to_string()
            } else {
                format!("https://{ch}")
            }
        } else {
            let u = self.object_url(key);
            // strip path for rebuild — object_url already has path
            return Ok(format!(
                "{u}?{canonical_querystring}&X-Amz-Signature={signature}"
            ));
        };
        let path = if key.is_empty() {
            String::new()
        } else {
            format!("/{key}")
        };
        Ok(format!(
            "{base}{path}?{canonical_querystring}&X-Amz-Signature={signature}"
        ))
    }
}

// ---------- helpers ----------

fn normalize_key_prefix(p: &str) -> String {
    let s = p.trim().trim_matches('/').to_string();
    if s.is_empty() || s == "0" {
        String::new()
    } else {
        s
    }
}

fn hex_sha256(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn hex_hmac(key: &[u8], data: &[u8]) -> String {
    hex::encode(hmac_sha256(key, data))
}

fn get_signature_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac_sha256(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

fn epoch_to_amz_date(secs: u64) -> String {
    // YYYYMMDD'T'HHMMSS'Z'
    let days = secs / 86400;
    let rem = secs % 86400;
    let hour = rem / 3600;
    let min = (rem % 3600) / 60;
    let sec = rem % 60;
    let (y, m, d) = civil_from_days(days as i64);
    format!("{y:04}{m:02}{d:02}T{hour:02}{min:02}{sec:02}Z")
}

// 日期换算统一走 drivers/timeutil（原为本地副本）
use super::timeutil::civil_from_days;

fn urlencoding_encode(s: &str) -> String {
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

fn canonicalize_query(query: &str) -> String {
    if query.is_empty() {
        return String::new();
    }
    let mut parts: Vec<(String, String)> = query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let mut it = p.splitn(2, '=');
            let k = it.next().unwrap_or("").to_string();
            let v = it.next().unwrap_or("").to_string();
            (k, v)
        })
        .collect();
    parts.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    parts
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn extract_xml_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let open2 = format!("<{tag} ");
    let close = format!("</{tag}>");
    let start = xml.find(&open).map(|i| i + open.len()).or_else(|| {
        xml.find(&open2)
            .and_then(|i| xml[i..].find('>').map(|j| i + j + 1))
    })?;
    let end = xml[start..].find(&close)? + start;
    Some(xml[start..end].trim().to_string())
}

fn extract_xml_tags(xml: &str, tag: &str) -> Vec<String> {
    let mut out = Vec::new();
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut rest = xml;
    while let Some(i) = rest.find(&open) {
        let start = i + open.len();
        if let Some(j) = rest[start..].find(&close) {
            out.push(rest[start..start + j].trim().to_string());
            rest = &rest[start + j + close.len()..];
        } else {
            break;
        }
    }
    out
}

fn extract_xml_blocks(xml: &str, tag: &str) -> Vec<String> {
    let mut out = Vec::new();
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut rest = xml;
    while let Some(i) = rest.find(&open) {
        let start = i;
        let content_start = i + open.len();
        if let Some(j) = rest[content_start..].find(&close) {
            let end = content_start + j + close.len();
            out.push(rest[start..end].to_string());
            rest = &rest[end..];
        } else {
            break;
        }
    }
    out
}

fn parse_rfc3339_ms(s: &str) -> Option<i64> {
    // 2024-01-02T03:04:05.000Z or 2024-01-02T03:04:05Z
    let s = s.trim();
    if s.len() < 19 {
        return None;
    }
    let y: i64 = s[0..4].parse().ok()?;
    let mo: i64 = s[5..7].parse().ok()?;
    let d: i64 = s[8..10].parse().ok()?;
    let h: i64 = s[11..13].parse().ok()?;
    let mi: i64 = s[14..16].parse().ok()?;
    let se: i64 = s[17..19].parse().ok()?;
    // rough days from epoch
    let days = days_from_civil(y as i32, mo as u32, d as u32);
    Some((days as i64 * 86400 + h * 3600 + mi * 60 + se) * 1000)
}

fn days_from_civil(y: i32, m: u32, d: u32) -> i32 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u32;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    (era * 146097 + doe as i32) - 719468
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n])
    }
}
