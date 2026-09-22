//! SMB 驱动（对齐 Go 版 drivers/smb）
//!
//! 纯 Rust 完整 SMB2/3 客户端体积与 musl/Android 静态链接成本较高。
//! 当前：校验 TCP 可达 + 配置可保存。
//!
//! 推荐临时方案：在宿主机挂载共享后使用「本机存储」驱动，例如：
//!   mount -t cifs //host/share /mnt/smb -o username=...,password=...
//! 完整协议读写将在后续引入专用 crate 后启用。

use super::{DownloadInfo, PutInput};
use crate::config::Entry;
use std::path::PathBuf;

pub struct Smb {
    address: String,
    username: String,
    password: String,
    share_name: String,
    root_path: String,
}

impl Smb {
    pub fn new(
        address: String,
        username: String,
        password: String,
        share_name: String,
        root_path: String,
    ) -> Self {
        let mut address = address.trim().to_string();
        if !address.contains(':') {
            address = format!("{address}:445");
        }
        let root_path = if root_path.trim().is_empty() || root_path.trim() == "." {
            String::new()
        } else {
            root_path.trim().to_string()
        };
        Smb {
            address,
            username,
            password,
            share_name,
            root_path,
        }
    }

    pub async fn validate(&self) -> Result<(), String> {
        if self.share_name.trim().is_empty() {
            return Err("SMB 需要 share_name（共享名）".into());
        }
        if self.username.trim().is_empty() {
            return Err("SMB 需要 username".into());
        }
        let _ = &self.password;
        match tokio::net::TcpStream::connect(&self.address).await {
            Ok(_) => Ok(()),
            Err(e) => Err(format!(
                "无法连接 SMB {}: {e}。可先在系统挂载后用「本机存储」驱动。",
                self.address
            )),
        }
    }

    pub async fn list(&self, _parent_fid: &str) -> Result<Vec<Entry>, String> {
        Err(format!(
            "SMB 协议读写尚未启用（已保存 //{}/{} user={} root={:?}）。\
请在系统挂载 CIFS 后使用「本机存储」，或等待后续版本接入纯 Rust SMB 客户端。",
            self.address, self.share_name, self.username, self.root_path
        ))
    }

    pub async fn download(&self, e: &Entry) -> Result<DownloadInfo, String> {
        if e.is_dir {
            return Err("目录无法下载".into());
        }
        Err("SMB 下载尚未启用（请用本机挂载 + local 驱动）".into())
    }

    pub async fn open_stream(&self, _e: &Entry) -> Result<(PathBuf, u64), String> {
        Err("SMB 流式读取尚未启用".into())
    }

    pub async fn mkdir(&self, _: &str, _: &str) -> Result<(), String> {
        Err("SMB 写操作尚未启用".into())
    }
    pub async fn rename(&self, _: &str, _: &Entry, _: &str) -> Result<(), String> {
        Err("SMB 写操作尚未启用".into())
    }
    pub async fn move_entry(&self, _: &str, _: &Entry, _: &str) -> Result<(), String> {
        Err("SMB 写操作尚未启用".into())
    }
    pub async fn copy(&self, _: &str, _: &Entry, _: &str) -> Result<(), String> {
        Err("SMB 写操作尚未启用".into())
    }
    pub async fn remove(&self, _: &str, _: &Entry) -> Result<(), String> {
        Err("SMB 写操作尚未启用".into())
    }
    pub async fn put(&self, _: &str, _: PutInput) -> Result<(), String> {
        Err("SMB 写操作尚未启用".into())
    }
}
