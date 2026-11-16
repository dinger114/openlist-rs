//! SFTP 驱动（对齐 Go 版 drivers/sftp）
//!
//! 基于 russh + russh-sftp：列表 / 下载流 / 建目录 / 重命名 / 移动 / 删除 / 上传。

use super::{DownloadInfo, PutInput};
use crate::config::{Entry, Store};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct Sftp {
    address: String,
    username: String,
    password: String,
    private_key: String,
    passphrase: String,
    root_path: String,
    ignore_symlink_error: bool,
    /// 已钉扎的主机公钥指纹（空 = TOFU 首次连接）；TOFU 成功后就地更新
    host_key_fingerprint: std::sync::RwLock<String>,
    /// 首连观测到的指纹回写用；None = 无持久化通道（如单测/CLI）
    store: Option<Arc<Store>>,
    account_id: String,
}

/// SSH 主机密钥校验回调。
///
/// 旧实现无条件 `Ok(true)`，等于跳过 SSH 的服务器身份认证 —— 任何能劫持路由/DNS
/// 的攻击者都可伪装成 SFTP 服务器拿到网盘凭据。现在实现 TOFU：
/// 首次连接信任并记录指纹，之后不匹配即拒绝（钉扎）。
struct Handler {
    /// 期望指纹（None = 首次连接，信任并记录）
    expected: Option<String>,
    /// 本次握手观测到的指纹，连接成功后回写配置
    observed: Arc<Mutex<Option<String>>>,
}

impl Handler {
    /// 指纹比对（抽出来便于单测）
    fn key_matches(expected: Option<&str>, observed: &str) -> bool {
        match expected {
            Some(want) if !want.is_empty() => want == observed,
            _ => true, // TOFU 首次：信任
        }
    }
}

impl russh::client::Handler for Handler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let fp = server_public_key
            .public_key()
            .fingerprint(russh::keys::HashAlg::Sha256)
            .to_string();
        *self.observed.lock().unwrap_or_else(|e| e.into_inner()) = Some(fp.clone());
        Ok(Self::key_matches(self.expected.as_deref(), &fp))
    }
}

/// SFTP 驱动构造参数（字段较多，打包成结构体避免 clippy too_many_arguments）
pub struct SftpConfig {
    pub address: String,
    pub username: String,
    pub password: String,
    pub private_key: String,
    pub passphrase: String,
    pub root_path: String,
    pub ignore_symlink_error: bool,
    pub host_key_fingerprint: String,
}

impl Sftp {
    pub fn new(cfg: SftpConfig, store: Option<Arc<Store>>, account_id: String) -> Self {
        let SftpConfig {
            address,
            username,
            password,
            private_key,
            passphrase,
            root_path,
            ignore_symlink_error,
            host_key_fingerprint,
        } = cfg;
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
            host_key_fingerprint: std::sync::RwLock::new(host_key_fingerprint.trim().to_string()),
            store,
            account_id,
        }
    }

    fn resolve(&self, fid: &str) -> String {
        // 归一化到 root_path 之下（折叠 .. 与多余斜杠，禁止逃出挂载根）
        super::normalize_fid(&self.root_path, fid)
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
        let observed = Arc::new(Mutex::new(None));
        let pinned = self.host_key_fingerprint.read().unwrap().clone();
        let handler = Handler {
            expected: if pinned.is_empty() { None } else { Some(pinned.clone()) },
            observed: observed.clone(),
        };
        let mut session = russh::client::connect(config, self.address.as_str(), handler)
            .await
            .map_err(|e| {
                let seen = observed.lock().unwrap_or_else(|e| e.into_inner()).clone();
                match (pinned.is_empty(), seen) {
                    // 钉扎态下握手失败且已观测到指纹 → 明确告诉管理员是主机密钥变了
                    (false, Some(fp)) => format!(
                        "SSH 连接失败 {}: {e}（主机密钥不匹配，实际指纹 {fp}。\
                         若确认服务端换过密钥，请在账号设置里清空 host_key_fingerprint 重新信任）",
                        self.address
                    ),
                    _ => format!("SSH 连接失败 {}: {e}", self.address),
                }
            })?;

        // TOFU：首次连接（配置里没有指纹）握手成功 → 把观测到的指纹写回配置。
        // 写库失败不阻断本次连接（否则首连永远失败），但会在日志里留下痕迹。
        if pinned.is_empty() {
            if let Some(fp) = observed.lock().unwrap_or_else(|e| e.into_inner()).clone() {
                // 先就地钉扎：否则本实例后续每次重连都是 expected=None（盲信任）
                *self.host_key_fingerprint.write().unwrap() = fp.clone();
                if let Some(st) = &self.store {
                    let id = self.account_id.clone();
                    st.update_credential(&id, |cred| {
                        if let crate::config::Credential::Sftp {
                            host_key_fingerprint, ..
                        } = cred
                        {
                            *host_key_fingerprint = fp;
                        }
                    });
                }
            }
        }

        // russh 0.63: authenticate_* 返回 AuthResult，用 .success() 取布尔
        let auth_ok = if !self.private_key.trim().is_empty() {
            let key_data = self.private_key.clone();
            let key = if self.passphrase.is_empty() {
                russh::keys::decode_secret_key(&key_data, None)
            } else {
                russh::keys::decode_secret_key(&key_data, Some(&self.passphrase))
            }
            .map_err(|e| format!("解析私钥失败: {e}"))?;
            session
                .authenticate_publickey(
                    &self.username,
                    russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), None),
                )
                .await
                .map_err(|e| format!("公钥认证失败: {e}"))?
        } else {
            session
                .authenticate_password(&self.username, &self.password)
                .await
                .map_err(|e| format!("密码认证失败: {e}"))?
        };
        if !auth_ok.success() {
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
        super::validate_name(new_name)?;
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
        super::validate_name(&input.name)?;
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

#[cfg(test)]
mod tests {
    use super::Handler;

    /// TOFU 首次（无期望指纹）→ 信任
    #[test]
    fn tofu_trusts_first_seen_key() {
        assert!(Handler::key_matches(None, "SHA256:abc"));
        assert!(Handler::key_matches(Some(""), "SHA256:abc"));
    }

    /// 已钉扎 → 指纹一致才放行
    #[test]
    fn pinned_key_must_match_exactly() {
        assert!(Handler::key_matches(Some("SHA256:abc"), "SHA256:abc"));
        assert!(!Handler::key_matches(Some("SHA256:abc"), "SHA256:xyz"));
    }

    /// 中间人换钥场景：钉扎的指纹与实际不符 → 拒绝
    #[test]
    fn mitm_different_key_rejected() {
        let pinned = "SHA256:uU8Z0m2vUx1Pz0F0kZ0w6c3n8s5r2q9t4b7y1e0a3d6g";
        let attacker = "SHA256:AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLL";
        assert!(!Handler::key_matches(Some(pinned), attacker));
    }
}
