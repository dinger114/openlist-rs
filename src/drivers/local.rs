//! 本机存储驱动（对齐 Go 版 drivers/local，浏览 + 下载 + 完整写操作）
//!
//! - fid 直接使用本机文件路径（根目录 = 配置的 root_path）
//! - list：read_dir 枚举
//! - download：返回 local_path，由 api 层直接从磁盘流式读取（不走 reqwest）
//! - 写操作：mkdir/rename/move/copy/remove/put 全部直接映射到 std::fs / tokio::fs

use super::DownloadInfo;
use crate::config::Entry;
use std::path::{Path, PathBuf};

pub struct Local {
    root_path: String,
}

impl Local {
    pub fn new(root_path: String) -> Self {
        Local { root_path }
    }

    /// 对齐 Init()：校验挂载目录存在且为目录
    pub fn validate(&self) -> Result<(), String> {
        let p = Path::new(&self.root_path);
        if !p.exists() {
            return Err(format!("本机存储路径不存在: {}", self.root_path));
        }
        if !p.is_dir() {
            return Err(format!("本机存储路径不是目录: {}", self.root_path));
        }
        Ok(())
    }

    /// fid("0"/"") -> 根目录；其余 fid 即目录路径
    fn resolve_dir(&self, fid: &str) -> PathBuf {
        if fid.is_empty() || fid == "0" {
            PathBuf::from(&self.root_path)
        } else {
            PathBuf::from(fid)
        }
    }

    pub fn list(&self, parent_fid: &str) -> Result<Vec<Entry>, String> {
        let dir = self.resolve_dir(parent_fid);
        let rd = std::fs::read_dir(&dir).map_err(|e| format!("读取目录 {} 失败: {e}", dir.display()))?;
        let mut out = Vec::new();
        for entry in rd {
            let Ok(entry) = entry else { continue };
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            // 元数据失败（如悬空符号链接）直接跳过
            let Ok(meta) = entry.metadata() else { continue };
            let is_dir = meta.is_dir();
            let size = if is_dir { 0 } else { meta.len() };
            let updated_at = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_millis() as i64);
            out.push(Entry {
                fid: path.to_string_lossy().to_string(),
                name,
                size,
                is_dir,
                updated_at,
                etag: None,
                s3_key_flag: None,
                file_type: None,
                extra: None,
            });
        }
        Ok(out)
    }

    pub fn download(&self, e: &Entry) -> Result<DownloadInfo, String> {
        if e.is_dir {
            return Err("目录无法下载".into());
        }
        let p = PathBuf::from(&e.fid);
        if !p.is_file() {
            return Err(format!("文件不存在: {}", e.fid));
        }
        Ok(DownloadInfo {
            url: String::new(),
            headers: vec![],
            proxy: true,
            local_path: Some(e.fid.clone()),
        })
    }

    /// 目标路径是否落在挂载目录内（防逃逸：拒绝 .. 逃出 root_path）
    fn ensure_inside_root(&self, p: &Path) -> Result<(), String> {
        let root = Path::new(&self.root_path);
        let canon = |path: &Path| -> Option<PathBuf> {
            // 逐段规范化（组件可能尚不存在，用 lexical 清理）
            let mut out = PathBuf::new();
            for comp in path.components() {
                match comp {
                    std::path::Component::ParentDir => {
                        out.pop();
                    }
                    c => out.push(c.as_os_str()),
                }
            }
            Some(out)
        };
        match (canon(root), canon(p)) {
            (Some(r), Some(t)) if t.starts_with(&r) => Ok(()),
            _ => Err(format!("路径越界: {}", p.display())),
        }
    }

    /// 对齐 MakeDir：父目录 + 名称 -> std::fs::create_dir
    pub fn mkdir(&self, parent_fid: &str, name: &str) -> Result<(), String> {
        let dir = self.resolve_dir(parent_fid);
        let target = dir.join(name);
        self.ensure_inside_root(&target)?;
        std::fs::create_dir_all(&target)
            .map_err(|e| format!("创建目录 {} 失败: {e}", target.display()))
    }

    /// 对齐 Rename：std::fs::rename（保留原扩展名语义由调用方决定，这里直接改名）
    pub fn rename(&self, _parent_fid: &str, e: &Entry, new_name: &str) -> Result<(), String> {
        if new_name.contains(['/', '\\']) {
            return Err("名称不能包含路径分隔符".into());
        }
        let src = PathBuf::from(&e.fid);
        self.ensure_inside_root(&src)?;
        let dst = match src.parent() {
            Some(p) => p.join(new_name),
            None => return Err("无法解析父目录".into()),
        };
        self.ensure_inside_root(&dst)?;
        std::fs::rename(&src, &dst)
            .map_err(|e| format!("重命名 {} -> {} 失败: {e}", src.display(), dst.display()))
    }

    /// 对齐 Move：跨目录 rename；跨盘符/卷时降级为 copy + delete
    pub fn move_entry(
        &self,
        parent_fid: &str,
        e: &Entry,
        dst_dir_fid: &str,
    ) -> Result<(), String> {
        let src = PathBuf::from(&e.fid);
        let dst_dir = self.resolve_dir(dst_dir_fid);
        let dst = dst_dir.join(&e.name);
        self.ensure_inside_root(&src)?;
        self.ensure_inside_root(&dst)?;
        let _ = parent_fid;
        if dst.exists() {
            return Err(format!("目标已存在: {}", dst.display()));
        }
        match std::fs::rename(&src, &dst) {
            Ok(()) => Ok(()),
            Err(_) => {
                // 跨卷 rename 失败（Windows EXDEV 等价场景）：copy + delete
                self.copy_entry(&src, &dst)?;
                if e.is_dir {
                    std::fs::remove_dir_all(&src)
                } else {
                    std::fs::remove_file(&src)
                }
                .map_err(|err| format!("移动后清理源失败: {err}"))
            }
        }
    }

    /// 对齐 Copy：文件逐字节复制；目录递归复制
    pub fn copy(&self, _parent_fid: &str, e: &Entry, dst_dir_fid: &str) -> Result<(), String> {
        let src = PathBuf::from(&e.fid);
        let dst_dir = self.resolve_dir(dst_dir_fid);
        let dst = dst_dir.join(&e.name);
        self.ensure_inside_root(&src)?;
        self.ensure_inside_root(&dst)?;
        if dst.exists() {
            return Err(format!("目标已存在: {}", dst.display()));
        }
        self.copy_entry(&src, &dst)
    }

    fn copy_entry(&self, src: &Path, dst: &Path) -> Result<(), String> {
        if src.is_dir() {
            std::fs::create_dir_all(dst)
                .map_err(|e| format!("创建目录 {} 失败: {e}", dst.display()))?;
            let rd = std::fs::read_dir(src)
                .map_err(|e| format!("读取目录 {} 失败: {e}", src.display()))?;
            for item in rd {
                let Ok(item) = item else { continue };
                let child_src = item.path();
                let child_dst = dst.join(item.file_name());
                self.copy_entry(&child_src, &child_dst)?;
            }
            Ok(())
        } else {
            std::fs::copy(src, dst)
                .map(|_| ())
                .map_err(|e| format!("复制 {} -> {} 失败: {e}", src.display(), dst.display()))
        }
    }

    /// 对齐 Remove：文件删除 / 目录递归删除（Go 版 local 用 os.RemoveAll）
    pub fn remove(&self, _parent_fid: &str, e: &Entry) -> Result<(), String> {
        let p = PathBuf::from(&e.fid);
        self.ensure_inside_root(&p)?;
        if e.is_dir {
            std::fs::remove_dir_all(&p).map_err(|err| format!("删除目录失败: {err}"))
        } else {
            std::fs::remove_file(&p).map_err(|err| format!("删除文件失败: {err}"))
        }
    }

    /// 对齐 Put：流式写盘（进度由调用方的 ProgressReader 统计）
    pub async fn put(&self, dst_dir_fid: &str, input: super::PutInput) -> Result<(), String> {
        use tokio::io::AsyncWriteExt;
        let dir = self.resolve_dir(dst_dir_fid);
        let target = dir.join(&input.name);
        self.ensure_inside_root(&target)?;
        let mut reader = input.reader;
        let mut file = tokio::fs::File::create(&target)
            .await
            .map_err(|e| format!("创建文件 {} 失败: {e}", target.display()))?;
        tokio::io::copy(&mut reader, &mut file)
            .await
            .map_err(|e| format!("写入文件失败: {e}"))?;
        file.flush()
            .await
            .map_err(|e| format!("刷新文件失败: {e}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_dir() {
        let d = Local::new("/tmp/root".into());
        assert_eq!(d.resolve_dir("0"), PathBuf::from("/tmp/root"));
        assert_eq!(d.resolve_dir(""), PathBuf::from("/tmp/root"));
        assert_eq!(d.resolve_dir("/tmp/root/sub"), PathBuf::from("/tmp/root/sub"));
    }
}
