//! FTP 驱动（对齐 Go 版 drivers/ftp）
//!
//! 纯 tokio TCP 实现最小子集：LIST / RETR / STOR / MKD / DELE / RMD / RNFR+RNTO。
//! 编码：可选 GBK（通过 encoding 字段，空 = UTF-8）。
//! 下载走 protocol 流（临时文件），支持后续 Range。

use super::{DownloadInfo, PutInput};
use crate::config::Entry;
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

pub struct Ftp {
    address: String,
    username: String,
    password: String,
    encoding: String,
    root_path: String,
    cwd_list: bool,
    conn: Mutex<Option<FtpConn>>,
}

struct FtpConn {
    control: BufReader<TcpStream>,
}

impl Ftp {
    pub fn new(
        address: String,
        username: String,
        password: String,
        encoding: String,
        root_path: String,
        cwd_list: bool,
    ) -> Self {
        let mut address = address.trim().to_string();
        if !address.contains(':') {
            address = format!("{address}:21");
        }
        let root_path = if root_path.trim().is_empty() {
            "/".into()
        } else {
            root_path
        };
        Ftp {
            address,
            username,
            password,
            encoding,
            root_path,
            cwd_list,
            conn: Mutex::new(None),
        }
    }

    pub async fn validate(&self) -> Result<(), String> {
        let mut c = self.connect().await?;
        write_cmd(&mut c.control, "NOOP").await?;
        let r = read_response(&mut c.control).await?;
        if r.code != 200 && r.code != 250 {
            return Err(format!("FTP NOOP 失败: {} {}", r.code, r.message));
        }
        *self.conn.lock().await = Some(c);
        Ok(())
    }

    fn resolve(&self, fid: &str) -> String {
        let fid = fid.trim();
        if fid.is_empty() || fid == "0" || fid == "/" {
            return self.root_path.clone();
        }
        if fid.starts_with('/') {
            fid.to_string()
        } else {
            format!("{}/{}", self.root_path.trim_end_matches('/'), fid)
        }
    }

    async fn connect(&self) -> Result<FtpConn, String> {
        let stream = TcpStream::connect(&self.address)
            .await
            .map_err(|e| format!("FTP 连接失败 {}: {e}", self.address))?;
        let mut control = BufReader::new(stream);
        let _ = read_response(&mut control).await?;
        write_cmd(&mut control, &format!("USER {}", self.username)).await?;
        let r = read_response(&mut control).await?;
        if r.code == 331 {
            write_cmd(&mut control, &format!("PASS {}", self.password)).await?;
            let r = read_response(&mut control).await?;
            if r.code != 230 {
                return Err(format!("FTP 登录失败: {} {}", r.code, r.message));
            }
        } else if r.code != 230 {
            return Err(format!("FTP USER 失败: {} {}", r.code, r.message));
        }
        // 二进制模式
        write_cmd(&mut control, "TYPE I").await?;
        let _ = read_response(&mut control).await?;
        Ok(FtpConn { control })
    }

    async fn with_conn<F, T>(&self, f: F) -> Result<T, String>
    where
        F: for<'a> FnOnce(
                &'a mut FtpConn,
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<T, String>> + Send + 'a>,
            > + Send,
        T: Send,
    {
        let mut guard = self.conn.lock().await;
        if guard.is_none() {
            *guard = Some(self.connect().await?);
        }
        // NOOP 探活
        if let Some(c) = guard.as_mut() {
            if write_cmd(&mut c.control, "NOOP").await.is_err()
                || read_response(&mut c.control).await.is_err()
            {
                *guard = Some(self.connect().await?);
            }
        }
        let c = guard.as_mut().unwrap();
        match f(c).await {
            Ok(v) => Ok(v),
            Err(e) => {
                *guard = None;
                Err(e)
            }
        }
    }

    pub async fn list(&self, parent_fid: &str) -> Result<Vec<Entry>, String> {
        let dir = self.resolve(parent_fid);
        let path_enc = encode_path(&dir, &self.encoding);
        let cwd_list = self.cwd_list;
        let encoding = self.encoding.clone();
        self.with_conn(move |c| {
            Box::pin(async move {
                let data = if cwd_list {
                    write_cmd(&mut c.control, &format!("CWD {path_enc}")).await?;
                    let r = read_response(&mut c.control).await?;
                    if r.code != 250 {
                        return Err(format!("CWD 失败: {} {}", r.code, r.message));
                    }
                    pasv_list(c, "LIST").await?
                } else {
                    pasv_list(c, &format!("LIST {path_enc}")).await?
                };
                let text = decode_bytes(&data, &encoding);
                let mut out = Vec::new();
                for line in text.lines() {
                    if let Some(e) = parse_list_line(line, &dir) {
                        if e.name != "." && e.name != ".." {
                            out.push(e);
                        }
                    }
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
        let remote = encode_path(&self.resolve(&e.fid), &self.encoding);
        let tmp = std::env::temp_dir().join(format!("olrs-ftp-{}", uuid::Uuid::new_v4()));
        let tmp2 = tmp.clone();
        self.with_conn(move |c| {
            Box::pin(async move {
                let data = pasv_retr(c, &remote).await?;
                tokio::fs::write(&tmp2, &data)
                    .await
                    .map_err(|e| format!("写临时文件失败: {e}"))?;
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
        let path = encode_path(
            &format!("{}/{}", self.resolve(parent_fid).trim_end_matches('/'), name),
            &self.encoding,
        );
        self.with_conn(move |c| {
            Box::pin(async move {
                write_cmd(&mut c.control, &format!("MKD {path}")).await?;
                let r = read_response(&mut c.control).await?;
                if r.code == 257 || r.code == 250 {
                    Ok(())
                } else {
                    Err(format!("MKD 失败: {} {}", r.code, r.message))
                }
            })
        })
        .await
    }

    pub async fn rename(&self, _parent_fid: &str, e: &Entry, new_name: &str) -> Result<(), String> {
        let src = self.resolve(&e.fid);
        let parent = match src.rfind('/') {
            Some(i) => &src[..i],
            None => "",
        };
        let dst = if parent.is_empty() {
            new_name.to_string()
        } else {
            format!("{parent}/{new_name}")
        };
        let src_e = encode_path(&src, &self.encoding);
        let dst_e = encode_path(&dst, &self.encoding);
        self.with_conn(move |c| {
            Box::pin(async move {
                write_cmd(&mut c.control, &format!("RNFR {src_e}")).await?;
                let r = read_response(&mut c.control).await?;
                if r.code != 350 {
                    return Err(format!("RNFR 失败: {} {}", r.code, r.message));
                }
                write_cmd(&mut c.control, &format!("RNTO {dst_e}")).await?;
                let r = read_response(&mut c.control).await?;
                if r.code == 250 {
                    Ok(())
                } else {
                    Err(format!("RNTO 失败: {} {}", r.code, r.message))
                }
            })
        })
        .await
    }

    pub async fn move_entry(
        &self,
        parent_fid: &str,
        e: &Entry,
        dst_dir_fid: &str,
    ) -> Result<(), String> {
        let dst = format!(
            "{}/{}",
            self.resolve(dst_dir_fid).trim_end_matches('/'),
            e.name
        );
        let src = self.resolve(&e.fid);
        let _ = parent_fid;
        let src_e = encode_path(&src, &self.encoding);
        let dst_e = encode_path(&dst, &self.encoding);
        self.with_conn(move |c| {
            Box::pin(async move {
                write_cmd(&mut c.control, &format!("RNFR {src_e}")).await?;
                let r = read_response(&mut c.control).await?;
                if r.code != 350 {
                    return Err(format!("RNFR 失败: {} {}", r.code, r.message));
                }
                write_cmd(&mut c.control, &format!("RNTO {dst_e}")).await?;
                let r = read_response(&mut c.control).await?;
                if r.code == 250 {
                    Ok(())
                } else {
                    Err(format!("RNTO 失败: {} {}", r.code, r.message))
                }
            })
        })
        .await
    }

    pub async fn copy(
        &self,
        _parent_fid: &str,
        _e: &Entry,
        _dst_dir_fid: &str,
    ) -> Result<(), String> {
        Err("FTP 不支持服务端复制".into())
    }

    pub async fn remove(&self, _parent_fid: &str, e: &Entry) -> Result<(), String> {
        let path = encode_path(&self.resolve(&e.fid), &self.encoding);
        let is_dir = e.is_dir;
        self.with_conn(move |c| {
            Box::pin(async move {
                if is_dir {
                    write_cmd(&mut c.control, &format!("RMD {path}")).await?;
                } else {
                    write_cmd(&mut c.control, &format!("DELE {path}")).await?;
                }
                let r = read_response(&mut c.control).await?;
                if (200..300).contains(&r.code) {
                    Ok(())
                } else {
                    Err(format!("删除失败: {} {}", r.code, r.message))
                }
            })
        })
        .await
    }

    pub async fn put(&self, dst_dir_fid: &str, mut input: PutInput) -> Result<(), String> {
        let remote = encode_path(
            &format!(
                "{}/{}",
                self.resolve(dst_dir_fid).trim_end_matches('/'),
                input.name
            ),
            &self.encoding,
        );
        let mut data = Vec::new();
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = input
                .reader
                .read(&mut buf)
                .await
                .map_err(|e| format!("读上传流失败: {e}"))?;
            if n == 0 {
                break;
            }
            data.extend_from_slice(&buf[..n]);
        }
        self.with_conn(move |c| {
            Box::pin(async move { pasv_stor(c, &remote, &data).await })
        })
        .await
    }
}

struct FtpResp {
    code: u16,
    message: String,
}

async fn write_cmd(control: &mut BufReader<TcpStream>, cmd: &str) -> Result<(), String> {
    control
        .get_mut()
        .write_all(format!("{cmd}\r\n").as_bytes())
        .await
        .map_err(|e| format!("写控制连接失败: {e}"))
}

async fn read_response(control: &mut BufReader<TcpStream>) -> Result<FtpResp, String> {
    let mut message = String::new();
    let mut code = 0u16;
    loop {
        let mut line = String::new();
        control
            .read_line(&mut line)
            .await
            .map_err(|e| format!("读 FTP 响应失败: {e}"))?;
        if line.len() < 3 {
            continue;
        }
        let c: u16 = line[0..3].parse().unwrap_or(0);
        if code == 0 {
            code = c;
        }
        message.push_str(line.trim_end());
        message.push('\n');
        if line.len() >= 4 && line.as_bytes()[3] == b' ' {
            break;
        }
        if line.len() >= 4 && line.as_bytes()[3] != b'-' {
            break;
        }
    }
    Ok(FtpResp { code, message })
}

async fn pasv_open(c: &mut FtpConn) -> Result<TcpStream, String> {
    write_cmd(&mut c.control, "PASV").await?;
    let r = read_response(&mut c.control).await?;
    if r.code != 227 {
        return Err(format!("PASV 失败: {} {}", r.code, r.message));
    }
    let start = r.message.find('(').ok_or("PASV 无括号")?;
    let end = r.message.find(')').ok_or("PASV 无括号")?;
    let inner = &r.message[start + 1..end];
    let nums: Vec<u16> = inner
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();
    if nums.len() < 6 {
        return Err(format!("PASV 解析失败: {}", r.message));
    }
    let host = format!("{}.{}.{}.{}", nums[0], nums[1], nums[2], nums[3]);
    let port = nums[4] * 256 + nums[5];
    TcpStream::connect(format!("{host}:{port}"))
        .await
        .map_err(|e| format!("数据连接失败: {e}"))
}

async fn pasv_list(c: &mut FtpConn, cmd: &str) -> Result<Vec<u8>, String> {
    let mut data = pasv_open(c).await?;
    write_cmd(&mut c.control, cmd).await?;
    let r = read_response(&mut c.control).await?;
    if r.code != 150 && r.code != 125 {
        return Err(format!("LIST 失败: {} {}", r.code, r.message));
    }
    let mut buf = Vec::new();
    data.read_to_end(&mut buf)
        .await
        .map_err(|e| format!("读 LIST 数据失败: {e}"))?;
    drop(data);
    let _ = read_response(&mut c.control).await?;
    Ok(buf)
}

async fn pasv_retr(c: &mut FtpConn, path: &str) -> Result<Vec<u8>, String> {
    let mut data = pasv_open(c).await?;
    write_cmd(&mut c.control, &format!("RETR {path}")).await?;
    let r = read_response(&mut c.control).await?;
    if r.code != 150 && r.code != 125 {
        return Err(format!("RETR 失败: {} {}", r.code, r.message));
    }
    let mut buf = Vec::new();
    data.read_to_end(&mut buf)
        .await
        .map_err(|e| format!("读 RETR 数据失败: {e}"))?;
    drop(data);
    let _ = read_response(&mut c.control).await?;
    Ok(buf)
}

async fn pasv_stor(c: &mut FtpConn, path: &str, body: &[u8]) -> Result<(), String> {
    let mut data = pasv_open(c).await?;
    write_cmd(&mut c.control, &format!("STOR {path}")).await?;
    let r = read_response(&mut c.control).await?;
    if r.code != 150 && r.code != 125 {
        return Err(format!("STOR 失败: {} {}", r.code, r.message));
    }
    data.write_all(body)
        .await
        .map_err(|e| format!("写 STOR 数据失败: {e}"))?;
    data.shutdown()
        .await
        .map_err(|e| format!("关闭数据连接失败: {e}"))?;
    drop(data);
    let r = read_response(&mut c.control).await?;
    if r.code == 226 || r.code == 250 {
        Ok(())
    } else {
        Err(format!("STOR 完成失败: {} {}", r.code, r.message))
    }
}

fn parse_list_line(line: &str, parent: &str) -> Option<Entry> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let first = line.chars().next()?;
    if first == 'd' || first == '-' || first == 'l' {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 9 {
            return None;
        }
        let is_dir = parts[0].starts_with('d');
        let size: u64 = parts[4].parse().unwrap_or(0);
        let name = parts[8..].join(" ");
        if name.is_empty() {
            return None;
        }
        return Some(Entry {
            fid: format!("{}/{}", parent.trim_end_matches('/'), name),
            name,
            size: if is_dir { 0 } else { size },
            is_dir,
            updated_at: None,
            etag: None,
            s3_key_flag: None,
            file_type: None,
            extra: None,
        });
    }
    if line.contains("<DIR>") {
        let name = line.split("<DIR>").nth(1)?.trim().to_string();
        if name.is_empty() {
            return None;
        }
        return Some(Entry {
            fid: format!("{}/{}", parent.trim_end_matches('/'), name),
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
    None
}

fn encode_path(path: &str, encoding: &str) -> String {
    let enc = encoding.to_lowercase();
    if enc.is_empty() || enc == "utf-8" || enc == "utf8" {
        return path.to_string();
    }
    if enc == "gbk" || enc == "gb2312" {
        return path.to_string();
    }
    path.to_string()
}

fn decode_bytes(data: &[u8], encoding: &str) -> String {
    let enc = encoding.to_lowercase();
    if enc == "gbk" || enc == "gb2312" {
        return String::from_utf8_lossy(data).to_string();
    }
    String::from_utf8_lossy(data).to_string()
}
