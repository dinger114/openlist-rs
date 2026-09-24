//! 本机存储驱动（对齐 Go 版 drivers/local，浏览 + 下载 + 完整写操作）
//!
//! - fid 直接使用本机文件路径（根目录 = 配置的 root_path）
//! - list：read_dir 枚举
//! - download：返回 local_path，由 api 层直接从磁盘流式读取（不走 reqwest）
//! - 写操作：mkdir/rename/move/copy/remove/put 全部直接映射到 std::fs / tokio::fs
//! - 边界：所有对外方法（含只读的 list/download）都先过 `ensure_inside_root`，
//!   否则登录用户可以用 `fid=/etc` 列目录、`fid=/etc/passwd` 下载任意文件
//! - 线程：同步文件系统调用统一丢进 tokio 阻塞线程池（spawn_blocking），
//!   不占住 async worker（递归 copy 大目录尤其明显）

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

    /// 在 tokio 阻塞线程池上执行同步文件系统操作
    async fn blocking<T, F>(&self, what: &str, f: F) -> Result<T, String>
    where
        F: FnOnce() -> Result<T, String> + Send + 'static,
        T: Send + 'static,
    {
        match tokio::task::spawn_blocking(f).await {
            Ok(r) => r,
            Err(e) => Err(format!("{what}任务执行失败: {e}")),
        }
    }

    pub async fn list(&self, parent_fid: &str) -> Result<Vec<Entry>, String> {
        let dir = self.resolve_dir(parent_fid);
        self.ensure_inside_root(&dir)?;
        self.blocking("枚举目录", move || list_dir(&dir)).await
    }

    pub async fn download(&self, e: &Entry) -> Result<DownloadInfo, String> {
        if e.is_dir {
            return Err("目录无法下载".into());
        }
        let p = PathBuf::from(&e.fid);
        self.ensure_inside_root(&p)?;
        let path = p.clone();
        if !self
            .blocking("读取文件信息", move || Ok(path.is_file()))
            .await?
        {
            return Err(format!("文件不存在: {}", e.fid));
        }
        Ok(DownloadInfo {
            url: String::new(),
            headers: vec![],
            proxy: true,
            local_path: Some(e.fid.clone()),
        })
    }

    /// 目标路径是否落在挂载目录内（防逃逸：拒绝 `..` 逃出 root_path）
    ///
    /// 纯词法判断（不解析符号链接）：调用方只能通过本驱动的 mkdir 建目录，
    /// 无法自行创建软链，因此 root 内软链指向外部这条路径在 API 层不可达。
    fn ensure_inside_root(&self, p: &Path) -> Result<(), String> {
        if lexically_inside(Path::new(&self.root_path), p) {
            Ok(())
        } else {
            Err(format!("路径越界: {}", p.display()))
        }
    }

    /// 对齐 MakeDir：父目录 + 名称 -> std::fs::create_dir
    pub async fn mkdir(&self, parent_fid: &str, name: &str) -> Result<(), String> {
        let target = self.resolve_dir(parent_fid).join(name);
        self.ensure_inside_root(&target)?;
        self.blocking("创建目录", move || {
            std::fs::create_dir_all(&target)
                .map_err(|e| format!("创建目录 {} 失败: {e}", target.display()))
        })
        .await
    }

    /// 对齐 Rename：std::fs::rename（保留原扩展名语义由调用方决定，这里直接改名）
    pub async fn rename(&self, _parent_fid: &str, e: &Entry, new_name: &str) -> Result<(), String> {
        if new_name.contains(['/', '\\']) {
            return Err("名称不能包含路径分隔符".into());
        }
        let src = PathBuf::from(&e.fid);
        self.ensure_inside_root(&src)?;
        let dst = src
            .parent()
            .ok_or_else(|| "无法解析父目录".to_string())?
            .join(new_name);
        self.ensure_inside_root(&dst)?;
        self.blocking("重命名", move || {
            std::fs::rename(&src, &dst)
                .map_err(|e| format!("重命名 {} -> {} 失败: {e}", src.display(), dst.display()))
        })
        .await
    }

    /// 对齐 Move：跨目录 rename；跨盘符/卷时降级为 copy + delete
    pub async fn move_entry(
        &self,
        _parent_fid: &str,
        e: &Entry,
        dst_dir_fid: &str,
    ) -> Result<(), String> {
        let src = PathBuf::from(&e.fid);
        let dst = self.resolve_dir(dst_dir_fid).join(&e.name);
        self.ensure_inside_root(&src)?;
        self.ensure_inside_root(&dst)?;
        self.blocking("移动", move || move_on_fs(&src, &dst)).await
    }

    /// 对齐 Copy：文件逐字节复制；目录递归复制
    pub async fn copy(
        &self,
        _parent_fid: &str,
        e: &Entry,
        dst_dir_fid: &str,
    ) -> Result<(), String> {
        let src = PathBuf::from(&e.fid);
        let dst = self.resolve_dir(dst_dir_fid).join(&e.name);
        self.ensure_inside_root(&src)?;
        self.ensure_inside_root(&dst)?;
        self.blocking("复制", move || {
            if dst.exists() {
                return Err(format!("目标已存在: {}", dst.display()));
            }
            copy_tree(&src, &dst)
        })
        .await
    }

    /// 对齐 Remove：文件删除 / 目录递归删除（Go 版 local 用 os.RemoveAll）
    pub async fn remove(&self, _parent_fid: &str, e: &Entry) -> Result<(), String> {
        let p = PathBuf::from(&e.fid);
        self.ensure_inside_root(&p)?;
        let is_dir = e.is_dir;
        self.blocking("删除", move || {
            if is_dir {
                std::fs::remove_dir_all(&p).map_err(|err| format!("删除目录失败: {err}"))
            } else {
                std::fs::remove_file(&p).map_err(|err| format!("删除文件失败: {err}"))
            }
        })
        .await
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

/// 逐段词法规范化后判断 `p` 是否位于 `root` 之内（`..` 只会回退，不会逃逸）
fn lexically_inside(root: &Path, p: &Path) -> bool {
    fn norm(path: &Path) -> PathBuf {
        let mut out = PathBuf::new();
        for comp in path.components() {
            match comp {
                std::path::Component::ParentDir => {
                    out.pop();
                }
                c => out.push(c.as_os_str()),
            }
        }
        out
    }
    norm(p).starts_with(norm(root))
}

/// read_dir 枚举（同步实现，由 `blocking` 调用）
fn list_dir(dir: &Path) -> Result<Vec<Entry>, String> {
    let rd = std::fs::read_dir(dir).map_err(|e| format!("读取目录 {} 失败: {e}", dir.display()))?;
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

/// 跨目录 rename；跨卷失败（Windows EXDEV 等价场景）时降级为 copy + delete
fn move_on_fs(src: &Path, dst: &Path) -> Result<(), String> {
    if dst.exists() {
        return Err(format!("目标已存在: {}", dst.display()));
    }
    match std::fs::rename(src, dst) {
        Ok(()) => Ok(()),
        Err(_) => {
            copy_tree(src, dst)?;
            if src.is_dir() {
                std::fs::remove_dir_all(src)
            } else {
                std::fs::remove_file(src)
            }
            .map_err(|err| format!("移动后清理源失败: {err}"))
        }
    }
}

/// 文件逐字节复制；目录递归复制（目标顶层是否已存在由调用方检查）
fn copy_tree(src: &Path, dst: &Path) -> Result<(), String> {
    if src.is_dir() {
        std::fs::create_dir_all(dst)
            .map_err(|e| format!("创建目录 {} 失败: {e}", dst.display()))?;
        let rd =
            std::fs::read_dir(src).map_err(|e| format!("读取目录 {} 失败: {e}", src.display()))?;
        for item in rd {
            let Ok(item) = item else { continue };
            copy_tree(&item.path(), &dst.join(item.file_name()))?;
        }
        Ok(())
    } else {
        std::fs::copy(src, dst)
            .map(|_| ())
            .map_err(|e| format!("复制 {} -> {} 失败: {e}", src.display(), dst.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(fid: &str, is_dir: bool) -> Entry {
        Entry {
            fid: fid.to_string(),
            name: fid.rsplit('/').next().unwrap_or(fid).to_string(),
            size: 0,
            is_dir,
            updated_at: None,
            etag: None,
            s3_key_flag: None,
            file_type: None,
            extra: None,
        }
    }

    #[test]
    fn test_resolve_dir() {
        let d = Local::new("/tmp/root".into());
        assert_eq!(d.resolve_dir("0"), PathBuf::from("/tmp/root"));
        assert_eq!(d.resolve_dir(""), PathBuf::from("/tmp/root"));
        assert_eq!(
            d.resolve_dir("/tmp/root/sub"),
            PathBuf::from("/tmp/root/sub")
        );
    }

    #[test]
    fn test_ensure_inside_root() {
        let d = Local::new("/tmp/root".into());
        // 挂载目录内（含同级前缀目录必须区分开）
        assert!(d.ensure_inside_root(Path::new("/tmp/root")).is_ok());
        assert!(d
            .ensure_inside_root(Path::new("/tmp/root/sub/a.txt"))
            .is_ok());
        assert!(d
            .ensure_inside_root(Path::new("/tmp/root/sub/../other/a.txt"))
            .is_ok());
        // 越界
        assert!(d.ensure_inside_root(Path::new("/etc")).is_err());
        assert!(d.ensure_inside_root(Path::new("/etc/passwd")).is_err());
        assert!(d.ensure_inside_root(Path::new("/tmp/root2")).is_err());
        assert!(d
            .ensure_inside_root(Path::new("/tmp/root/../../etc/passwd"))
            .is_err());
    }

    #[tokio::test]
    async fn test_list_rejects_outside_root() {
        let d = Local::new("/tmp".into());
        let err = d.list("/etc").await.unwrap_err();
        assert!(err.contains("路径越界"), "unexpected: {err}");
    }

    #[tokio::test]
    async fn test_download_rejects_outside_root() {
        let d = Local::new("/tmp".into());
        let err = d.download(&entry("/etc/passwd", false)).await.unwrap_err();
        assert!(err.contains("路径越界"), "unexpected: {err}");
    }

    #[tokio::test]
    async fn test_rename_rejects_path_separator() {
        let d = Local::new("/tmp".into());
        let err = d
            .rename("0", &entry("/tmp/a.txt", false), "../b.txt")
            .await
            .unwrap_err();
        assert!(err.contains("不能包含路径分隔符"), "unexpected: {err}");
    }
}
