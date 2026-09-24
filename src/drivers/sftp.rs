//! SFTP 驱动（对齐 Go 版 drivers/sftp）
//!
//! 基于 russh + russh-sftp：列表 / 下载流 / 建目录 / 重命名 / 移动 / 删除 / 上传。

use super::{DownloadInfo, PutInput};
use crate::config::Entry;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct Sftp {
    address: String,
    username: String,
    password: String,
    private_key: String,
    passphrase: String,
    root_path: String,
    ignore_symlink_error: bool,
}

struct Handler;

#[async_trait::async_trait]
impl russh::client::Handler for Handler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh_keys::key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

impl Sftp {
    pub fn new(
        address: String,
        username: String,
        password: String,
        private_key: String,
        passphrase: String,
        root_path: String,
        ignore_symlink_error: bool,
    ) -> Self {
        let mut address = address.trim().to_string();
        if !address.contains(':') {
            address = format!("{address}:22");
        }
        let root_path = if root_path.trim().is_empty() {
            "/".into()
        } else {
            root_path.trim().to_string()
        };
        Sftp {
            address,
            username,
            password,
            private_key,
            passphrase,
            root_path,
            ignore_symlink_error,
        }
    }

    fn resolve(&self, fid: &str) -> String {
        let fid = fid.trim();
        if fid.is_empty() || fid == "0" {
            return self.root_path.clone();
        }
        if fid.starts_with('/') {
            if self.root_path == "/" {
                fid.to_string()
            } else {
                format!("{}{}", self.root_path.trim_end_matches('/'), fid)
            }
        } else {
            format!("{}/{}", self.root_path.trim_end_matches('/'), fid)
        }
    }

    async fn with_sftp<F, T>(&self, f: F) -> Result<T, String>
    where
        F: for<'a> FnOnce(
                &'a mut russh_sftp::client::SftpSession,
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<T, String>> + Send + 'a>,
            > + Send,
        T: Send,
    {
        let config = russh::client::Config::default();
        let config = Arc::new(config);
        let mut session = russh::client::connect(config, self.address.as_str(), Handler)
            .await
            .map_err(|e| format!("SSH 连接失败 {}: {e}", self.address))?;

        // russh 0.45: authenticate_* 返回 Result<bool, Error>（无 .success()）
        let auth_ok = if !self.private_key.trim().is_empty() {
            let key_data = self.private_key.clone();
            let key = if self.passphrase.is_empty() {
                russh_keys::decode_secret_key(&key_data, None)
            } else {
                russh_keys::decode_secret_key(&key_data, Some(&self.passphrase))
            }
            .map_err(|e| format!("解析私钥失败: {e}"))?;
            session
                .authenticate_publickey(&self.username, Arc::new(key))
                .await
                .map_err(|e| format!("公钥认证失败: {e}"))?
        } else {
            session
                .authenticate_password(&self.username, &self.password)
                .await
                .map_err(|e| format!("密码认证失败: {e}"))?
        };
        if !auth_ok {
            return Err("SFTP 认证失败（用户名/密码/私钥）".into());
        }

        let channel = session
            .channel_open_session()
            .await
            .map_err(|e| format!("打开 channel 失败: {e}"))?;
        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(|e| format!("请求 sftp 子系统失败: {e}"))?;
        let mut sftp = russh_sftp::client::SftpSession::new(channel.into_stream())
            .await
            .map_err(|e| format!("SFTP 握手失败: {e}"))?;

        let out = f(&mut sftp).await?;
        let _ = sftp.close().await;
        Ok(out)
    }

    pub async fn validate(&self) -> Result<(), String> {
        if self.username.trim().is_empty() {
            return Err("SFTP 需要 username".into());
        }
        if self.password.is_empty() && self.private_key.is_empty() {
            return Err("SFTP 需要 password 或 private_key".into());
        }
        self.with_sftp(|sftp| {
            Box::pin(async move {
                let _ = sftp
                    .read_dir(".")
                    .await
                    .map_err(|e| format!("SFTP 列目录失败: {e}"))?;
                Ok(())
            })
        })
        .await
    }

    pub async fn list(&self, parent_fid: &str) -> Result<Vec<Entry>, String> {
        let path = self.resolve(parent_fid);
        let ignore = self.ignore_symlink_error;
        let root = self.root_path.clone();
        self.with_sftp(move |sftp| {
            Box::pin(async move {
                let entries = sftp
                    .read_dir(&path)
                    .await
                    .map_err(|e| format!("SFTP list {path}: {e}"))?;
                let mut out = Vec::new();
                for e in entries {
                    let name = e.file_name();
                    if name == "." || name == ".." {
                        continue;
                    }
                    let meta = e.metadata();
                    let is_dir = meta.file_type().is_dir();
                    let is_link = meta.file_type().is_symlink();
                    if is_link && ignore {
                        let full = join_path(&path, &name);
                        match sftp.metadata(&full).await {
                            Ok(m) => {
                                let is_dir = m.file_type().is_dir();
                                out.push(entry_from(
                                    &root,
                                    &path,
                                    &name,
                                    is_dir,
                                    m.size.unwrap_or(0),
                                ));
                            }
                            Err(_) => continue,
                        }
                        continue;
                    }
                    out.push(entry_from(
                        &root,
                        &path,
                        &name,
                        is_dir,
                        meta.size.unwrap_or(0),
                    ));
                }
                Ok(out)
            })
        })
        .await
    }

    pub async fn download(&self, e: &Entry) -> Result<DownloadInfo, String> {
        if e.is_dir {
            return Err("目录无法下载".into());
        }
        Ok(DownloadInfo {
            url: String::new(),
            headers: vec![],
            proxy: true,
            local_path: None,
        })
    }

    pub async fn open_stream(&self, e: &Entry) -> Result<(PathBuf, u64), String> {
        let remote = self.resolve(&e.fid);
        let tmp = std::env::temp_dir().join(format!("olrs-sftp-{}", uuid::Uuid::new_v4()));
        let tmp2 = tmp.clone();
        self.with_sftp(move |sftp| {
            Box::pin(async move {
                let mut remote_file = sftp
                    .open(&remote)
                    .await
                    .map_err(|e| format!("SFTP open {remote}: {e}"))?;
                let mut local = tokio::fs::File::create(&tmp2)
                    .await
                    .map_err(|e| format!("创建临时文件: {e}"))?;
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    let n = remote_file
                        .read(&mut buf)
                        .await
                        .map_err(|e| format!("SFTP read: {e}"))?;
                    if n == 0 {
                        break;
                    }
                    local
                        .write_all(&buf[..n])
                        .await
                        .map_err(|e| format!("写临时: {e}"))?;
                }
                local.flush().await.ok();
                Ok(())
            })
        })
        .await?;
        let len = tokio::fs::metadata(&tmp)
            .await
            .map(|m| m.len())
            .unwrap_or(0);
        Ok((tmp, len))
    }

    pub async fn mkdir(&self, parent_fid: &str, name: &str) -> Result<(), String> {
        let path = join_path(&self.resolve(parent_fid), name);
        self.with_sftp(move |sftp| {
            Box::pin(async move {
                sftp.create_dir(&path)
                    .await
                    .map_err(|e| format!("SFTP mkdir: {e}"))?;
                Ok(())
            })
        })
        .await
    }

    pub async fn rename(&self, _parent_fid: &str, e: &Entry, new_name: &str) -> Result<(), String> {
        let src = self.resolve(&e.fid);
        let parent = src.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
        let dst = if parent.is_empty() {
            format!("/{new_name}")
        } else {
            format!("{parent}/{new_name}")
        };
        self.with_sftp(move |sftp| {
            Box::pin(async move {
                sftp.rename(&src, &dst)
                    .await
                    .map_err(|e| format!("SFTP rename: {e}"))?;
                Ok(())
            })
        })
        .await
    }

    pub async fn move_entry(
        &self,
        _parent_fid: &str,
        e: &Entry,
        dst_dir_fid: &str,
    ) -> Result<(), String> {
        let src = self.resolve(&e.fid);
        let dst = join_path(&self.resolve(dst_dir_fid), &e.name);
        self.with_sftp(move |sftp| {
            Box::pin(async move {
                sftp.rename(&src, &dst)
                    .await
                    .map_err(|e| format!("SFTP move: {e}"))?;
                Ok(())
            })
        })
        .await
    }

    pub async fn copy(
        &self,
        _parent_fid: &str,
        e: &Entry,
        dst_dir_fid: &str,
    ) -> Result<(), String> {
        let src = self.resolve(&e.fid);
        let dst = join_path(&self.resolve(dst_dir_fid), &e.name);
        if e.is_dir {
            return Err("SFTP 暂不支持目录复制".into());
        }
        self.with_sftp(move |sftp| {
            Box::pin(async move {
                let mut rf = sftp
                    .open(&src)
                    .await
                    .map_err(|e| format!("open src: {e}"))?;
                let mut wf = sftp
                    .create(&dst)
                    .await
                    .map_err(|e| format!("create dst: {e}"))?;
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    let n = rf.read(&mut buf).await.map_err(|e| e.to_string())?;
                    if n == 0 {
                        break;
                    }
                    wf.write_all(&buf[..n]).await.map_err(|e| e.to_string())?;
                }
                Ok(())
            })
        })
        .await
    }

    pub async fn remove(&self, _parent_fid: &str, e: &Entry) -> Result<(), String> {
        let path = self.resolve(&e.fid);
        let is_dir = e.is_dir;
        self.with_sftp(move |sftp| {
            Box::pin(async move {
                if is_dir {
                    sftp.remove_dir(&path)
                        .await
                        .map_err(|e| format!("SFTP rmdir: {e}"))?;
                } else {
                    sftp.remove_file(&path)
                        .await
                        .map_err(|e| format!("SFTP rm: {e}"))?;
                }
                Ok(())
            })
        })
        .await
    }

    pub async fn put(&self, dst_dir_fid: &str, mut input: PutInput) -> Result<(), String> {
        let path = join_path(&self.resolve(dst_dir_fid), &input.name);
        self.with_sftp(move |sftp| {
            Box::pin(async move {
                let mut wf = sftp
                    .create(&path)
                    .await
                    .map_err(|e| format!("SFTP create: {e}"))?;
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    let n = input
                        .reader
                        .read(&mut buf)
                        .await
                        .map_err(|e| format!("读流: {e}"))?;
                    if n == 0 {
                        break;
                    }
                    wf.write_all(&buf[..n])
                        .await
                        .map_err(|e| format!("SFTP write: {e}"))?;
                }
                Ok(())
            })
        })
        .await
    }
}

fn join_path(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{}/{name}", parent.trim_end_matches('/'))
    }
}

fn entry_from(root: &str, parent: &str, name: &str, is_dir: bool, size: u64) -> Entry {
    let full = join_path(parent, name);
    let fid = if root == "/" {
        full.clone()
    } else if let Some(rest) = full.strip_prefix(root.trim_end_matches('/')) {
        if rest.is_empty() {
            "/".into()
        } else {
            rest.to_string()
        }
    } else {
        full.clone()
    };
    Entry {
        fid,
        name: name.to_string(),
        size: if is_dir { 0 } else { size },
        is_dir,
        updated_at: None,
        etag: None,
        s3_key_flag: None,
        file_type: None,
        extra: None,
    }
}
