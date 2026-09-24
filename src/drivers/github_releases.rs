//! GitHub Releases 驱动（对齐 Go 版 drivers/github_releases）
//!
//! - repo_structure: 多行或逗号分隔，形如 `[path:]org/repo`
//! - 默认展示 latest release 的 assets；可选展示全部版本
//! - 只读，无上传

use super::{DownloadInfo, PutInput};
use crate::config::Entry;
use reqwest::Client;
use serde_json::Value;

pub struct GithubReleases {
    points: Vec<MountPoint>,
    token: String,
    show_all_version: bool,
    show_source_code: bool,
    gh_proxy: String,
    per_page: u32,
    max_page: u32,
    http: Client,
}

struct MountPoint {
    /// 虚拟挂载路径，如 "/openlist" 或 "/"
    point: String,
    /// org/repo
    repo: String,
}

impl GithubReleases {
    pub fn new(
        repo_structure: String,
        token: String,
        show_all_version: bool,
        show_source_code: bool,
        gh_proxy: String,
        per_page: u32,
        max_page: u32,
    ) -> Self {
        let points = parse_repos(&repo_structure);
        GithubReleases {
            points,
            token,
            show_all_version,
            show_source_code,
            gh_proxy: gh_proxy.trim().trim_end_matches('/').to_string(),
            per_page: if per_page == 0 { 30 } else { per_page.min(100) },
            max_page,
            http: Client::new(),
        }
    }

    pub async fn validate(&self) -> Result<(), String> {
        if self.points.is_empty() {
            return Err(
                "GitHub Releases 需要至少一条 repo_structure（如 OpenListTeam/OpenList）".into(),
            );
        }
        let repo = &self.points[0].repo;
        let (status, body) = self.api_get(&format!("/repos/{repo}")).await?;
        if status == 404 {
            return Err(format!("仓库不存在或无权访问: {repo}"));
        }
        if status == 401 || status == 403 {
            return Err(format!(
                "GitHub 认证/限流失败 ({status}): {}",
                truncate(&body, 200)
            ));
        }
        if !(200..300).contains(&status) {
            return Err(format!(
                "GitHub API 失败 ({status}): {}",
                truncate(&body, 200)
            ));
        }
        Ok(())
    }

    async fn api_get(&self, path: &str) -> Result<(u16, String), String> {
        let url = format!("https://api.github.com{path}");
        let mut req = self
            .http
            .get(&url)
            .header("User-Agent", "openlist-rs")
            .header("Accept", "application/vnd.github+json");
        if !self.token.is_empty() {
            req = req.header("Authorization", format!("Bearer {}", self.token));
        }
        let resp = req
            .send()
            .await
            .map_err(|e| format!("GitHub 请求失败: {e}"))?;
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        Ok((status, text))
    }

    fn resolve_path(&self, fid: &str) -> String {
        let fid = fid.trim();
        if fid.is_empty() || fid == "0" {
            return "/".into();
        }
        if fid.starts_with('/') {
            fid.to_string()
        } else {
            format!("/{fid}")
        }
    }

    pub async fn list(&self, parent_fid: &str) -> Result<Vec<Entry>, String> {
        let path = self.resolve_path(parent_fid);
        let mut out = Vec::new();

        for point in &self.points {
            if !self.show_all_version {
                self.list_latest(point, &path, &mut out).await?;
            } else {
                self.list_all_versions(point, &path, &mut out).await?;
            }
        }
        out.sort_by(|a, b| a.fid.cmp(&b.fid));
        out.dedup_by(|a, b| a.fid == b.fid);
        Ok(out)
    }

    async fn list_latest(
        &self,
        point: &MountPoint,
        path: &str,
        out: &mut Vec<Entry>,
    ) -> Result<(), String> {
        if point.point == path {
            let release = self.fetch_latest(&point.repo).await?;
            if let Some(rel) = release {
                self.push_release_assets(point, &rel, "", out);
            }
        } else if point.point.starts_with(path) {
            if let Some(name) = next_dir(&point.point, path) {
                let fid = if path == "/" {
                    format!("/{name}")
                } else {
                    format!("{path}/{name}")
                };
                if !out.iter().any(|e| e.fid == fid) {
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
            }
        }
        Ok(())
    }

    async fn list_all_versions(
        &self,
        point: &MountPoint,
        path: &str,
        out: &mut Vec<Entry>,
    ) -> Result<(), String> {
        if point.point == path {
            let releases = self.fetch_all_releases(&point.repo).await?;
            for rel in releases {
                let tag = rel
                    .get("tag_name")
                    .and_then(|t| t.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                let fid = if point.point == "/" {
                    format!("/{tag}")
                } else {
                    format!("{}/{tag}", point.point.trim_end_matches('/'))
                };
                out.push(Entry {
                    fid,
                    name: tag,
                    size: 0,
                    is_dir: true,
                    updated_at: None,
                    etag: None,
                    s3_key_flag: None,
                    file_type: None,
                    extra: None,
                });
            }
        } else if let Some(tag) = path
            .strip_prefix(&format!("{}/", point.point.trim_end_matches('/')))
            .or_else(|| {
                if point.point == "/" {
                    path.strip_prefix('/')
                } else {
                    None
                }
            })
        {
            if !tag.contains('/') {
                let releases = self.fetch_all_releases(&point.repo).await?;
                if let Some(rel) = releases
                    .into_iter()
                    .find(|r| r.get("tag_name").and_then(|t| t.as_str()) == Some(tag))
                {
                    self.push_release_assets(point, &rel, tag, out);
                }
            }
        } else if point.point.starts_with(path) {
            if let Some(name) = next_dir(&point.point, path) {
                let fid = if path == "/" {
                    format!("/{name}")
                } else {
                    format!("{path}/{name}")
                };
                if !out.iter().any(|e| e.fid == fid) {
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
            }
        }
        Ok(())
    }

    fn push_release_assets(
        &self,
        point: &MountPoint,
        rel: &Value,
        tag: &str,
        out: &mut Vec<Entry>,
    ) {
        let assets = rel
            .get("assets")
            .and_then(|a| a.as_array())
            .cloned()
            .unwrap_or_default();
        for a in assets {
            let name = a
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .to_string();
            if name.is_empty() {
                continue;
            }
            let size = a.get("size").and_then(|s| s.as_u64()).unwrap_or(0);
            let url = a
                .get("browser_download_url")
                .and_then(|u| u.as_str())
                .unwrap_or("")
                .to_string();
            let base = if tag.is_empty() {
                point.point.trim_end_matches('/').to_string()
            } else if point.point == "/" {
                format!("/{tag}")
            } else {
                format!("{}/{tag}", point.point.trim_end_matches('/'))
            };
            let fid = if base.is_empty() || base == "/" {
                format!("/{name}")
            } else {
                format!("{base}/{name}")
            };
            out.push(Entry {
                fid,
                name,
                size,
                is_dir: false,
                updated_at: None,
                etag: if url.is_empty() { None } else { Some(url) },
                s3_key_flag: None,
                file_type: None,
                extra: None,
            });
        }
        if self.show_source_code {
            if let Some(zip) = rel.get("zipball_url").and_then(|u| u.as_str()) {
                let name = "Source code (zip)".to_string();
                let base = if tag.is_empty() {
                    point.point.trim_end_matches('/').to_string()
                } else if point.point == "/" {
                    format!("/{tag}")
                } else {
                    format!("{}/{tag}", point.point.trim_end_matches('/'))
                };
                let fid = if base.is_empty() || base == "/" {
                    format!("/{name}")
                } else {
                    format!("{base}/{name}")
                };
                out.push(Entry {
                    fid,
                    name,
                    size: 0,
                    is_dir: false,
                    updated_at: None,
                    etag: Some(zip.to_string()),
                    s3_key_flag: None,
                    file_type: None,
                    extra: None,
                });
            }
        }
    }

    async fn fetch_latest(&self, repo: &str) -> Result<Option<Value>, String> {
        let (status, body) = self
            .api_get(&format!("/repos/{repo}/releases/latest"))
            .await?;
        if status == 404 {
            return Ok(None);
        }
        if !(200..300).contains(&status) {
            return Err(format!(
                "获取 latest release 失败 ({status}): {}",
                truncate(&body, 200)
            ));
        }
        let v: Value = serde_json::from_str(&body).map_err(|e| format!("解析 release: {e}"))?;
        Ok(Some(v))
    }

    async fn fetch_all_releases(&self, repo: &str) -> Result<Vec<Value>, String> {
        let mut all = Vec::new();
        let mut page = 1u32;
        loop {
            if self.max_page > 0 && page > self.max_page {
                break;
            }
            let (status, body) = self
                .api_get(&format!(
                    "/repos/{repo}/releases?per_page={}&page={page}",
                    self.per_page
                ))
                .await?;
            if !(200..300).contains(&status) {
                return Err(format!(
                    "获取 releases 失败 ({status}): {}",
                    truncate(&body, 200)
                ));
            }
            let arr: Vec<Value> =
                serde_json::from_str(&body).map_err(|e| format!("解析 releases: {e}"))?;
            if arr.is_empty() {
                break;
            }
            let n = arr.len();
            all.extend(arr);
            if n < self.per_page as usize {
                break;
            }
            page += 1;
        }
        Ok(all)
    }

    pub async fn download(&self, e: &Entry) -> Result<DownloadInfo, String> {
        if e.is_dir {
            return Err("目录无法下载".into());
        }
        let mut url = e.etag.clone().unwrap_or_default();
        if url.is_empty() {
            return Err("无下载地址（请重新打开目录刷新）".into());
        }
        if !self.gh_proxy.is_empty() && url.contains("github.com") {
            if let Some(rest) = url.strip_prefix("https://github.com/") {
                url = format!("{}/{}", self.gh_proxy.trim_end_matches('/'), rest);
            }
        }
        Ok(DownloadInfo {
            url,
            headers: vec![],
            proxy: false,
            local_path: None,
        })
    }

    pub async fn mkdir(&self, _: &str, _: &str) -> Result<(), String> {
        Err("GitHub Releases 只读".into())
    }
    pub async fn rename(&self, _: &str, _: &Entry, _: &str) -> Result<(), String> {
        Err("GitHub Releases 只读".into())
    }
    pub async fn move_entry(&self, _: &str, _: &Entry, _: &str) -> Result<(), String> {
        Err("GitHub Releases 只读".into())
    }
    pub async fn copy(&self, _: &str, _: &Entry, _: &str) -> Result<(), String> {
        Err("GitHub Releases 只读".into())
    }
    pub async fn remove(&self, _: &str, _: &Entry) -> Result<(), String> {
        Err("GitHub Releases 只读".into())
    }
    pub async fn put(&self, _: &str, _: PutInput) -> Result<(), String> {
        Err("GitHub Releases 只读".into())
    }
}

fn parse_repos(s: &str) -> Vec<MountPoint> {
    let mut out = Vec::new();
    for line in s.split(['\n', ',', ';']) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (point, repo) = if let Some((p, r)) = line.split_once(':') {
            let p = p.trim();
            let r = r.trim();
            if r.contains('/') && (p.starts_with('/') || p.is_empty() || !p.contains('/')) {
                let point = if p.is_empty() {
                    "/".into()
                } else if p.starts_with('/') {
                    p.to_string()
                } else {
                    format!("/{p}")
                };
                (point, r.to_string())
            } else {
                ("/".into(), line.to_string())
            }
        } else {
            ("/".into(), line.to_string())
        };
        if repo.contains('/') {
            out.push(MountPoint { point, repo });
        }
    }
    if out.len() == 1 && out[0].point != "/" && !s.contains(':') {
        out[0].point = "/".into();
    }
    out
}

fn next_dir(point: &str, path: &str) -> Option<String> {
    let point = point.trim_end_matches('/');
    let path = if path == "/" {
        ""
    } else {
        path.trim_end_matches('/')
    };
    let rest = point.strip_prefix(path)?;
    let rest = rest.trim_start_matches('/');
    if rest.is_empty() {
        return None;
    }
    Some(rest.split('/').next()?.to_string())
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n])
    }
}
