//! 123PanLink 驱动（对齐 Go 版 drivers/123_link）
//!
//! 纯离线：从文本树构建目录结构，下载时对 URL 可选 auth_key 签名。
//! 文本结构：
//! ```text
//! FolderName:
//!   [FileSize:][Modified:]Url
//! ```

use super::DownloadInfo;
use crate::config::Entry;
use md5::{Digest, Md5};
use rand::Rng;
use std::sync::Mutex;

#[derive(Debug, Clone)]
struct Node {
    url: String,
    name: String,
    level: i32,
    modified: i64,
    size: i64,
    children: Vec<Node>,
}

impl Node {
    fn is_file(&self) -> bool {
        !self.url.is_empty()
    }

    fn cal_size(&mut self) -> i64 {
        if self.is_file() {
            return self.size;
        }
        let mut size = 0i64;
        for c in &mut self.children {
            size += c.cal_size();
        }
        self.size = size;
        size
    }

    fn get_by_path(&self, paths: &[&str]) -> Option<&Node> {
        if paths.is_empty() {
            return None;
        }
        if self.name != paths[0] {
            return None;
        }
        if paths.len() == 1 {
            return Some(self);
        }
        for child in &self.children {
            if let Some(n) = child.get_by_path(&paths[1..]) {
                return Some(n);
            }
        }
        None
    }
}

pub struct Pan123Link {
    root: Mutex<Node>,
    private_key: String,
    uid: u64,
    valid_duration_min: i64,
}

impl Pan123Link {
    pub fn new(
        origin_urls: String,
        private_key: String,
        uid: u64,
        valid_duration_min: i64,
    ) -> Result<Self, String> {
        let mut root = build_tree(&origin_urls)?;
        root.cal_size();
        Ok(Pan123Link {
            root: Mutex::new(root),
            private_key,
            uid,
            valid_duration_min: if valid_duration_min <= 0 {
                30
            } else {
                valid_duration_min
            },
        })
    }

    pub fn validate(&self) -> Result<(), String> {
        Ok(())
    }

    pub async fn list(&self, parent_fid: &str) -> Result<Vec<Entry>, String> {
        let path = if parent_fid.is_empty() || parent_fid == "0" || parent_fid == "/" {
            "/"
        } else {
            parent_fid
        };
        let root = self.root.lock().unwrap();
        let node = get_node_from_root(&root, path).ok_or_else(|| format!("路径不存在: {path}"))?;
        if node.is_file() {
            return Err("不是目录".into());
        }
        let mut out = Vec::new();
        for child in &node.children {
            let child_path = if path == "/" {
                format!("/{}", child.name)
            } else {
                format!("{}/{}", path.trim_end_matches('/'), child.name)
            };
            out.push(Entry {
                fid: child_path,
                name: child.name.clone(),
                size: child.size.max(0) as u64,
                is_dir: !child.is_file(),
                updated_at: if child.modified > 0 {
                    Some(child.modified * 1000)
                } else {
                    None
                },
                etag: None,
                s3_key_flag: None,
                file_type: None,
                extra: if child.is_file() {
                    Some(serde_json::json!({ "url": child.url }))
                } else {
                    None
                },
            });
        }
        Ok(out)
    }

    pub async fn download(&self, e: &Entry) -> Result<DownloadInfo, String> {
        if e.is_dir {
            return Err("目录无法下载".into());
        }
        let url = e
            .extra
            .as_ref()
            .and_then(|v| v.get("url"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .or_else(|| {
                // 回退：从树中按 fid 查
                let root = self.root.lock().unwrap();
                get_node_from_root(&root, &e.fid).map(|n| n.url.clone())
            })
            .filter(|u| !u.is_empty())
            .ok_or_else(|| "未找到文件 URL".to_string())?;

        let signed = sign_url(&url, &self.private_key, self.uid, self.valid_duration_min)?;
        Ok(DownloadInfo {
            url: signed,
            headers: vec![],
            proxy: false,
            local_path: None,
        })
    }

    pub async fn mkdir(&self, _parent_fid: &str, _name: &str) -> Result<(), String> {
        Err("123PanLink 为只读驱动，不支持此操作".into())
    }
    pub async fn rename(&self, _p: &str, _e: &Entry, _n: &str) -> Result<(), String> {
        Err("123PanLink 为只读驱动，不支持此操作".into())
    }
    pub async fn move_entry(&self, _p: &str, _e: &Entry, _d: &str) -> Result<(), String> {
        Err("123PanLink 为只读驱动，不支持此操作".into())
    }
    pub async fn copy(&self, _p: &str, _e: &Entry, _d: &str) -> Result<(), String> {
        Err("123PanLink 为只读驱动，不支持此操作".into())
    }
    pub async fn remove(&self, _p: &str, _e: &Entry) -> Result<(), String> {
        Err("123PanLink 为只读驱动，不支持此操作".into())
    }
    pub async fn put(&self, _d: &str, _input: super::PutInput) -> Result<(), String> {
        Err("123PanLink 为只读驱动，不支持此操作".into())
    }
}

fn get_node_from_root<'a>(root: &'a Node, path: &str) -> Option<&'a Node> {
    let parts = split_path(path);
    let refs: Vec<&str> = parts.iter().map(|s| s.as_str()).collect();
    root.get_by_path(&refs)
}

fn split_path(path: &str) -> Vec<String> {
    if path == "/" || path.is_empty() {
        return vec!["root".into()];
    }
    let mut parts: Vec<String> = path
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();
    parts.insert(0, "root".into());
    parts
}

fn build_tree(text: &str) -> Result<Node, String> {
    // 用索引栈模拟：存当前路径上各层在 children 中的位置
    // 简化：用递归结构，直接维护 stack of mutable indices via parent list
    // nodes stored as path of indices from root
    // 用 flatten 方式：每次找到父节点后 append
    // 为简单起见用指针模拟：Vec 持有所有节点，用索引引用
    // 更直接：用递归构建 — 这里用 stack of Vec indices into a flat tree

    // 采用与 Go 相同的栈结构，但用 Box 避免生命周期问题
    // 最终把 children 挂到 root 上

    // 用一个临时栈：每个元素是 (level, Node)
    // 当遇到同级或更浅时弹出并挂到父
    struct Frame {
        level: i32,
        node: Node,
    }
    let mut frames: Vec<Frame> = vec![Frame {
        level: -1,
        node: Node {
            url: String::new(),
            name: "root".into(),
            level: -1,
            modified: 0,
            size: 0,
            children: Vec::new(),
        },
    }];

    for line in text.lines() {
        let mut indent = 0;
        for ch in line.chars() {
            if ch == ' ' {
                indent += 1;
            } else {
                break;
            }
        }
        if indent % 2 != 0 {
            return Err(format!("缩进必须是 2 的倍数: {line}"));
        }
        let level = (indent / 2) as i32;
        let line = line[indent..].trim();
        if line.is_empty() {
            continue;
        }
        while frames.len() > 1 && level <= frames.last().unwrap().level {
            let Frame { node, .. } = frames.pop().unwrap();
            frames.last_mut().unwrap().node.children.push(node);
        }
        if line.ends_with(':') {
            let name = line.trim_end_matches(':').to_string();
            frames.push(Frame {
                level,
                node: Node {
                    url: String::new(),
                    name,
                    level,
                    modified: 0,
                    size: 0,
                    children: Vec::new(),
                },
            });
        } else {
            let mut node = parse_file_line(line)?;
            node.level = level;
            frames.last_mut().unwrap().node.children.push(node);
        }
    }
    // 弹出剩余
    while frames.len() > 1 {
        let Frame { node, .. } = frames.pop().unwrap();
        frames.last_mut().unwrap().node.children.push(node);
    }
    Ok(frames.pop().unwrap().node)
}

fn parse_file_line(line: &str) -> Result<Node, String> {
    let http_idx = line
        .find("https://")
        .or_else(|| line.find("http://"))
        .ok_or_else(|| format!("文件行必须包含 URL: {line}"))?;
    let url = line[http_idx..].to_string();
    let info = &line[..http_idx];

    let mut name = url::Url::parse(&url)
        .ok()
        .and_then(|u| {
            let segs: Vec<_> = u.path_segments()?.collect();
            segs.last().map(|s| percent_decode(s))
        })
        .unwrap_or_else(|| url.clone());
    if name.is_empty() {
        name = "unnamed".into();
    }

    let mut size = 0i64;
    let mut modified = chrono_now_unix();

    let info = info.trim();
    if !info.is_empty() {
        // 可能是 "name:" 或 "size:" 或 "size:modified:"
        let parts: Vec<&str> = info.split(':').filter(|s| !s.is_empty()).collect();
        // 若最后一段不是纯数字，则是 name
        if let Some(first) = parts.first() {
            if first.parse::<i64>().is_err() {
                name = first.to_string();
                if parts.len() >= 2 {
                    if let Ok(s) = parts[1].parse::<i64>() {
                        size = s;
                    }
                }
                if parts.len() >= 3 {
                    if let Ok(m) = parts[2].parse::<i64>() {
                        modified = m;
                    }
                }
            } else {
                // 全是数字：size[:modified]
                if let Ok(s) = parts[0].parse::<i64>() {
                    size = s;
                }
                if parts.len() >= 2 {
                    if let Ok(m) = parts[1].parse::<i64>() {
                        modified = m;
                    }
                }
            }
        }
        // 也兼容 "name:url" 这种 name 在 info 末尾带冒号的情况（Go: name from info before url）
        // 若 info 形如 "myname:"
        if info.ends_with(':') && parts.len() == 1 && parts[0].parse::<i64>().is_err() {
            name = parts[0].to_string();
        }
    }

    Ok(Node {
        url,
        name,
        level: 0,
        modified,
        size,
        children: Vec::new(),
    })
}

fn percent_decode(s: &str) -> String {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Ok(h), Ok(l)) = (
                u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 2]).unwrap_or(""), 16),
                u8::from_str_radix(std::str::from_utf8(&bytes[i + 2..i + 3]).unwrap_or(""), 16),
            ) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn chrono_now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// 对齐 Go SignURL
fn sign_url(origin: &str, private_key: &str, uid: u64, valid_min: i64) -> Result<String, String> {
    if private_key.is_empty() {
        return Ok(origin.to_string());
    }
    let mut u = url::Url::parse(origin).map_err(|e| format!("URL 解析失败: {e}"))?;
    let ts = chrono_now_unix() + valid_min * 60;
    let r_int: i64 = rand::thread_rng().gen::<i64>().abs();
    let path = u.path();
    let raw = format!("{path}-{ts}-{r_int}-{uid}-{private_key}");
    let digest = Md5::digest(raw.as_bytes());
    let auth_key = format!("{ts}-{r_int}-{uid}-{digest:x}");
    u.query_pairs_mut().append_pair("auth_key", &auth_key);
    Ok(u.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_tree() {
        let text = r#"folder1:
  name1:https://vip.123pan.com/29/a.mp3
  https://vip.123pan.com/29/b.mp3
folder2:
  https://vip.123pan.com/29/c.mp4
https://vip.123pan.com/29/d.zip
"#;
        let tree = build_tree(text).unwrap();
        assert_eq!(tree.children.len(), 3);
        assert_eq!(tree.children[0].name, "folder1");
        assert_eq!(tree.children[0].children.len(), 2);
        assert_eq!(tree.children[0].children[0].name, "name1");
        assert_eq!(tree.children[2].name, "d.zip");
    }

    #[test]
    fn test_sign_empty_key() {
        let u = sign_url("https://example.com/f", "", 0, 30).unwrap();
        assert_eq!(u, "https://example.com/f");
    }
}
