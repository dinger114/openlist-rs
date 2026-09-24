//! 百度网盘驱动（对齐 Go 版 drivers/baidu_netdisk，官方 openapi 通道）
//!
//! - 授权：refresh_token 刷新 access_token（默认走 olist 在线刷新 API）
//! - 列目录：GET /rest/2.0/xpan/file?method=list（按路径，start/limit 分页）
//! - 下载：GET /rest/2.0/xpan/multimedia?method=filemetas&fsids=[..]&dlink=1
//!   拿到 dlink 后追加 access_token 并跟随 302，访问需 UA "pan.baidu.com"
//! - 写操作：GET /rest/2.0/xpan/file?method=filemanager（rename/move/copy/delete）、
//!   method=create（建目录/建文件）
//! - 上传：precreate -> superfile2 逐片上传（4MB 分片、逐片 md5）-> create，
//!   支持整文件 md5 秒传与 uploadid 过期重试

use super::DownloadInfo;
use crate::config::{Credential, Entry, Store};
use md5::{Digest, Md5};
use reqwest::{redirect, Client, ClientBuilder, Method};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use uuid::Uuid;

const API: &str = "https://pan.baidu.com/rest/2.0";
const ONLINE_REFRESH_API: &str = "https://api.oplist.org/baiduyun/renewapi";
const DOWNLOAD_UA: &str = "pan.baidu.com";
/// 对齐 Go 版 UploadAPI 默认值 / UPLOAD_FALLBACK_API
const UPLOAD_API: &str = "https://d.pcs.baidu.com";
/// 对齐 Go 版 DefaultSliceSize（非会员固定 4MB；Rust 版未取 vip_type）
const SLICE_SIZE: u64 = 4 * 1024 * 1024;
/// 对齐 Go 版 SliceSize 常量（slice-md5 只算前 256KB）
const SLICE_MD5_SIZE: u64 = 256 * 1024;
/// 对齐 Go 版 DEFAULT_UPLOAD_SLICE_TIMEOUT（单分片上传超时 60s）
const UPLOAD_SLICE_TIMEOUT: u64 = 60;
/// 对齐 Go 版 ErrUploadIDExpired（uploadid 失效哨兵错误）
const ERR_UPLOADID_EXPIRED: &str = "uploadid expired";

/// create() 参数结构体（参数对齐 Go 版 create(path, size, isdir, uploadid, blockList, mtime, ctime)）
struct CreateArgs<'a> {
    path: &'a str,
    size: u64,
    isdir: i32,
    uploadid: &'a str,
    block_list: &'a str,
    mtime: i64,
    ctime: i64,
}

/// precreate() 参数结构体（参数对齐 Go 版 precreate(path, size, blockList, contentMd5, sliceMd5, ctime, mtime)）
struct PrecreateArgs<'a> {
    path: &'a str,
    size: u64,
    block_list_str: &'a str,
    content_md5: &'a str,
    slice_md5: &'a str,
    ctime: i64,
    mtime: i64,
}

/// upload_parts() 参数结构体（参数对齐 Go 版 uploadParts 内部循环入参）
struct UploadPartsArgs<'a> {
    path: &'a str,
    uploadid: &'a str,
    file_name: &'a str,
    tmp_path: &'a Path,
    count: u64,
    last_block_size: u64,
    pending: &'a mut [i64],
}

pub struct BaiduNetdisk {
    account_id: String,
    http: Client,
    http_no_redirect: Client,
    refresh_token: Mutex<String>,
    access_token: Mutex<String>,
    store: Arc<Store>,
}

impl BaiduNetdisk {
    pub fn new(
        account_id: &str,
        refresh_token: String,
        access_token: String,
        store: Arc<Store>,
    ) -> Self {
        BaiduNetdisk {
            account_id: account_id.to_string(),
            http: Client::new(),
            http_no_redirect: ClientBuilder::new()
                .redirect(redirect::Policy::none())
                .build()
                .unwrap(),
            refresh_token: Mutex::new(refresh_token),
            access_token: Mutex::new(access_token),
            store,
        }
    }

    fn save_tokens(&self, refresh: &str, access: &str) {
        *self.refresh_token.lock().unwrap() = refresh.to_string();
        *self.access_token.lock().unwrap() = access.to_string();
        let (r, a) = (refresh.to_string(), access.to_string());
        let id = self.account_id.clone();
        self.store.update_credential(&id, |cred| {
            if let Credential::BaiduNetdisk {
                refresh_token,
                access_token,
            } = cred
            {
                *refresh_token = r.clone();
                *access_token = a.clone();
            }
        });
    }

    fn access_token(&self) -> String {
        self.access_token.lock().unwrap().clone()
    }

    /// 对齐 Go 版 refreshToken()：olist 在线 API 刷新（重试一次防空 token）
    async fn refresh_token(&self) -> Result<(), String> {
        for _ in 0..2 {
            let cur = self.refresh_token.lock().unwrap().clone();
            let url = format!(
                "{}?refresh_ui={}&server_use=true&driver_txt=baiduyun_go",
                ONLINE_REFRESH_API,
                urlencode(&cur)
            );
            let resp = self
                .http
                .get(&url)
                .send()
                .await
                .map_err(|e| format!("刷新百度网盘 token 失败: {e}"))?;
            let v: Value = resp
                .json()
                .await
                .map_err(|e| format!("刷新响应解析失败: {e}"))?;
            let refresh = v
                .get("refresh_token")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let access = v
                .get("access_token")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            if !refresh.is_empty() && !access.is_empty() {
                self.save_tokens(&refresh, &access);
                return Ok(());
            }
        }
        Err("刷新百度网盘 token 失败：refresh_token 可能已失效".into())
    }

    /// 对齐 Go 版 request()：errno 111/-6 刷新 token 后重试
    async fn request(
        &self,
        method: Method,
        url: &str,
        params: &[(String, String)],
        retried: bool,
    ) -> Result<Value, String> {
        let req = self
            .http
            .request(method, url)
            .query(&[("access_token", self.access_token())])
            .query(params);
        let resp = req.send().await.map_err(|e| format!("请求失败: {e}"))?;
        let v: Value = resp
            .json()
            .await
            .map_err(|e| format!("响应解析失败: {e}"))?;
        let errno = v.get("errno").and_then(|x| x.as_i64()).unwrap_or(-1);
        if errno != 0 {
            if (errno == 111 || errno == -6) && !retried {
                self.refresh_token().await?;
                return Box::pin(self.request(Method::GET, url, params, true)).await;
            }
            return Err(format!(
                "百度网盘接口错误(errno={errno})，详见 https://pan.baidu.com/union/doc/"
            ));
        }
        Ok(v)
    }

    async fn get(&self, pathname: &str, params: &[(String, String)]) -> Result<Value, String> {
        self.request(Method::GET, &format!("{API}{pathname}"), params, false)
            .await
    }

    /// 对齐 Go 版 Init()：GET /xpan/nas?method=uinfo 验证 token
    pub async fn validate(&self) -> Result<(), String> {
        if self.access_token().is_empty() {
            self.refresh_token().await?;
        }
        self.get("/xpan/nas", &[("method".into(), "uinfo".into())])
            .await?;
        Ok(())
    }

    /// 对齐 Go 版 getFiles()：目录 fid 即网盘路径，start/limit 分页
    pub async fn list(&self, dir: &str) -> Result<Vec<Entry>, String> {
        // 根目录为 "/"（Go 版 DefaultRoot）；旧配置里可能存了兜底值 "0"
        let dir = match dir {
            "" | "0" => "/",
            other => other,
        };
        let mut files = Vec::new();
        let mut start: i64 = 0;
        let limit: i64 = 1000;
        loop {
            let params = vec![
                ("method".into(), "list".into()),
                ("dir".into(), dir.to_string()),
                ("web".into(), "web".into()),
                ("order".into(), "name".into()),
                ("start".into(), start.to_string()),
                ("limit".into(), limit.to_string()),
            ];
            let resp = self.get("/xpan/file", &params).await?;
            let list = resp
                .get("list")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            if list.is_empty() {
                break;
            }
            for f in &list {
                let path = f
                    .get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let fs_id = f.get("fs_id").and_then(|v| v.as_i64()).unwrap_or(0);
                files.push(Entry {
                    // fid = 完整路径（下载/列目录都以路径为键）
                    fid: path,
                    name: f
                        .get("server_filename")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    size: f.get("size").and_then(|v| v.as_u64()).unwrap_or(0),
                    is_dir: f.get("isdir").and_then(|v| v.as_i64()).unwrap_or(0) == 1,
                    updated_at: f
                        .get("server_mtime")
                        .and_then(|v| v.as_i64())
                        .map(|s| s * 1000),
                    etag: None,
                    s3_key_flag: None,
                    file_type: None,
                    // 下载 filemetas 需要 fs_id
                    extra: Some(json!({ "fsid": fs_id.to_string() })),
                });
            }
            if (list.len() as i64) < limit {
                break;
            }
            start += limit;
        }
        Ok(files)
    }

    /// 对齐 Go 版 linkOfficial()
    pub async fn download(&self, e: &Entry) -> Result<DownloadInfo, String> {
        let fsid = e
            .extra
            .as_ref()
            .and_then(|x| x.get("fsid"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if fsid.is_empty() {
            return Err("缺少文件 fs_id（请从文件列表发起下载）".into());
        }
        let params = vec![
            ("method".into(), "filemetas".into()),
            ("fsids".into(), format!("[{fsid}]")),
            ("dlink".into(), "1".into()),
        ];
        let resp = self.get("/xpan/multimedia", &params).await?;
        let dlink = resp
            .pointer("/list/0/dlink")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if dlink.is_empty() {
            return Err("百度网盘未返回 dlink".into());
        }
        let u = format!("{}&access_token={}", dlink, urlencode(&self.access_token()));
        // 跟随一次 302 拿真实直链
        let res = self
            .http_no_redirect
            .head(&u)
            .header("User-Agent", DOWNLOAD_UA)
            .send()
            .await
            .map_err(|e| format!("获取直链失败: {e}"))?;
        let final_url = res
            .headers()
            .get("location")
            .and_then(|l| l.to_str().ok())
            .unwrap_or(&u)
            .to_string();
        Ok(DownloadInfo {
            url: final_url,
            headers: vec![("User-Agent".into(), DOWNLOAD_UA.into())],
            proxy: true,
            local_path: None,
        })
    }

    /// 对齐 Go 版 postForm()：POST form 到 /rest/2.0 下接口，
    /// errno 111/-6（token 失效）刷新后重试一次
    async fn post_form(
        &self,
        pathname: &str,
        params: &[(String, String)],
        form: &[(String, String)],
    ) -> Result<Value, String> {
        let url = format!("{API}{pathname}");
        let mut retried = false;
        loop {
            let resp = self
                .http
                .post(&url)
                .query(&[("access_token", self.access_token())])
                .query(params)
                .form(form)
                .send()
                .await
                .map_err(|e| format!("请求失败: {e}"))?;
            let v: Value = resp
                .json()
                .await
                .map_err(|e| format!("响应解析失败: {e}"))?;
            let errno = v.get("errno").and_then(|x| x.as_i64()).unwrap_or(-1);
            if errno != 0 {
                if (errno == 111 || errno == -6) && !retried {
                    retried = true;
                    self.refresh_token().await?;
                    continue;
                }
                return Err(format!(
                    "百度网盘接口错误(errno={errno})，详见 https://pan.baidu.com/union/doc/"
                ));
            }
            return Ok(v);
        }
    }

    /// 对齐 Go 版 create()：POST /xpan/file?method=create
    async fn create(&self, args: CreateArgs<'_>) -> Result<Value, String> {
        let CreateArgs {
            path,
            size,
            isdir,
            uploadid,
            block_list,
            mtime,
            ctime,
        } = args;
        let params = vec![("method".to_string(), "create".to_string())];
        let mut form = vec![
            ("path".to_string(), path.to_string()),
            ("size".to_string(), size.to_string()),
            ("isdir".to_string(), isdir.to_string()),
            ("rtype".to_string(), "3".to_string()),
        ];
        if mtime != 0 && ctime != 0 {
            join_time(&mut form, ctime, mtime);
        }
        if !uploadid.is_empty() {
            form.push(("uploadid".to_string(), uploadid.to_string()));
        }
        if !block_list.is_empty() {
            form.push(("block_list".to_string(), block_list.to_string()));
        }
        self.post_form("/xpan/file", &params, &form).await
    }

    /// 对齐 Go 版 manage()：POST /xpan/file?method=filemanager&opera=..
    async fn manage(&self, opera: &str, filelist: Value) -> Result<(), String> {
        let params = vec![
            ("method".to_string(), "filemanager".to_string()),
            ("opera".to_string(), opera.to_string()),
        ];
        let form = vec![
            ("async".to_string(), "0".to_string()),
            (
                "filelist".to_string(),
                serde_json::to_string(&filelist).unwrap_or_default(),
            ),
            ("ondup".to_string(), "fail".to_string()),
        ];
        self.post_form("/xpan/file", &params, &form).await?;
        Ok(())
    }

    // ---------- 写操作（对齐 Go 版 MakeDir/Rename/Move/Copy/Remove） ----------

    /// 对齐 Go 版 MakeDir()：create(path, 0, isdir=1, ...)
    pub async fn mkdir(&self, parent_fid: &str, name: &str) -> Result<(), String> {
        let path = join_path(normalize_fid(parent_fid), name);
        self.create(CreateArgs {
            path: &path,
            size: 0,
            isdir: 1,
            uploadid: "",
            block_list: "",
            mtime: 0,
            ctime: 0,
        })
        .await?;
        Ok(())
    }

    /// 对齐 Go 版 Rename()：manage("rename", [{path, newname}])
    pub async fn rename(&self, _parent_fid: &str, e: &Entry, new_name: &str) -> Result<(), String> {
        self.manage("rename", json!([{ "path": e.fid, "newname": new_name }]))
            .await
    }

    /// 对齐 Go 版 Move()：manage("move", [{path, dest, newname}])
    pub async fn move_entry(
        &self,
        _parent_fid: &str,
        e: &Entry,
        dst_dir_fid: &str,
    ) -> Result<(), String> {
        self.manage(
            "move",
            json!([{
                "path": e.fid,
                "dest": normalize_fid(dst_dir_fid),
                "newname": e.name,
            }]),
        )
        .await
    }

    /// 对齐 Go 版 Copy()：manage("copy", [{path, dest, newname}])
    pub async fn copy(
        &self,
        _parent_fid: &str,
        e: &Entry,
        dst_dir_fid: &str,
    ) -> Result<(), String> {
        self.manage(
            "copy",
            json!([{
                "path": e.fid,
                "dest": normalize_fid(dst_dir_fid),
                "newname": e.name,
            }]),
        )
        .await
    }

    /// 对齐 Go 版 Remove()：manage("delete", [path, ..])
    pub async fn remove(&self, _parent_fid: &str, e: &Entry) -> Result<(), String> {
        self.manage("delete", json!([e.fid])).await
    }

    /// 对齐 Go 版 Put()：
    /// 1. 秒传（PutRapid）：仅凭整文件 md5 走 create，命中即完成
    /// 2. precreate（带 content-md5/slice-md5，return_type=2 也是秒传）
    /// 3. superfile2 逐片上传（失败重试 3 次；uploadid 过期则重新 precreate 后重来，最多两轮）
    /// 4. create（带 uploadid + block_list）落库
    ///
    /// 需要整文件 md5 / 前 256KB md5 / 逐片 md5 且分片需多次重读 →
    /// 先把 reader 落临时文件，边写边算所有 hash。
    pub async fn put(&self, dst_dir_fid: &str, input: super::PutInput) -> Result<(), String> {
        let path = join_path(normalize_fid(dst_dir_fid), &input.name);
        let tmp_path = temp_file_path();
        let _guard = TempFileGuard(tmp_path.clone());
        let spooled = spool_baidu(input.reader, &tmp_path).await?;
        let size = spooled.total;
        // 对齐 Go：百度网盘不允许上传空文件
        if size < 1 {
            return Err("百度网盘不允许上传空文件".into());
        }
        let count = size.div_ceil(SLICE_SIZE);
        let last_block_size = match size % SLICE_SIZE {
            0 => SLICE_SIZE,
            r => r,
        };
        let content_md5 = spooled.file_md5;
        let slice_md5 = spooled.slice_md5;
        let block_list_str = serde_json::to_string(&spooled.block_list).unwrap_or_default();
        // Go 用文件 mtime/ctime；上传流没有时间信息，用当前时间
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let (mtime, ctime) = (now, now);

        // step.0 秒传（对齐 Go PutRapid：block_list 只含整文件 md5）
        let rapid_block_list =
            serde_json::to_string(std::slice::from_ref(&content_md5)).unwrap_or_default();
        if self
            .create(CreateArgs {
                path: &path,
                size,
                isdir: 0,
                uploadid: "",
                block_list: &rapid_block_list,
                mtime,
                ctime,
            })
            .await
            .is_ok()
        {
            return Ok(());
        }

        // step.1 预上传
        let pre = self
            .precreate(PrecreateArgs {
                path: &path,
                size,
                block_list_str: &block_list_str,
                content_md5: &content_md5,
                slice_md5: &slice_md5,
                ctime,
                mtime,
            })
            .await?;
        if pre.return_type == 2 {
            // 秒传命中（服务端 md5 匹配）
            return Ok(());
        }
        let mut uploadid = pre.uploadid;
        let mut pending: Vec<i64> = pre.block_list;

        // step.2 上传分片（最多两轮，uploadid 过期则重新 precreate 后全量重传）
        for _round in 0..2 {
            match self
                .upload_parts(UploadPartsArgs {
                    path: &path,
                    uploadid: &uploadid,
                    file_name: &input.name,
                    tmp_path: &tmp_path,
                    count,
                    last_block_size,
                    pending: &mut pending,
                })
                .await
            {
                Ok(()) => break,
                Err(err) if err == ERR_UPLOADID_EXPIRED => {
                    // 对齐 Go：uploadid 过期，重新 precreate（不带 md5），所有分片重传
                    let new_pre = self
                        .precreate(PrecreateArgs {
                            path: &path,
                            size,
                            block_list_str: &block_list_str,
                            content_md5: "",
                            slice_md5: "",
                            ctime,
                            mtime,
                        })
                        .await?;
                    if new_pre.return_type == 2 {
                        return Ok(());
                    }
                    uploadid = new_pre.uploadid;
                    pending = new_pre.block_list;
                }
                Err(err) => return Err(err),
            }
        }

        // step.3 创建文件
        self.create(CreateArgs {
            path: &path,
            size,
            isdir: 0,
            uploadid: &uploadid,
            block_list: &block_list_str,
            mtime,
            ctime,
        })
        .await?;
        Ok(())
    }

    /// 对齐 Go 版 precreate()：POST /xpan/file?method=precreate
    async fn precreate(&self, args: PrecreateArgs<'_>) -> Result<PrecreateInfo, String> {
        let PrecreateArgs {
            path,
            size,
            block_list_str,
            content_md5,
            slice_md5,
            ctime,
            mtime,
        } = args;
        let params = vec![("method".to_string(), "precreate".to_string())];
        let mut form = vec![
            ("path".to_string(), path.to_string()),
            ("size".to_string(), size.to_string()),
            ("isdir".to_string(), "0".to_string()),
            ("autoinit".to_string(), "1".to_string()),
            ("rtype".to_string(), "3".to_string()),
            ("block_list".to_string(), block_list_str.to_string()),
        ];
        // 只有首次上传才带 content-md5 / slice-md5（对齐 Go）
        if !content_md5.is_empty() && !slice_md5.is_empty() {
            form.push(("content-md5".to_string(), content_md5.to_string()));
            form.push(("slice-md5".to_string(), slice_md5.to_string()));
        }
        join_time(&mut form, ctime, mtime);
        let v = self.post_form("/xpan/file", &params, &form).await?;
        Ok(PrecreateInfo {
            return_type: v.get("return_type").and_then(|x| x.as_i64()).unwrap_or(0),
            uploadid: v
                .get("uploadid")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            block_list: v
                .get("block_list")
                .and_then(|x| x.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_i64()).collect())
                .unwrap_or_default(),
        })
    }

    /// 对齐 Go 版分片上传循环：逐片 superfile2，单片失败重试 3 次（退避 1s/2s），
    /// uploadid 过期立即上抛（对齐 Go retry.RetryIf 不重试过期错误）
    async fn upload_parts(&self, args: UploadPartsArgs<'_>) -> Result<(), String> {
        let UploadPartsArgs {
            path,
            uploadid,
            file_name,
            tmp_path,
            count,
            last_block_size,
            pending,
        } = args;
        for slot in pending.iter_mut() {
            let partseq = *slot;
            if partseq < 0 {
                continue;
            }
            let offset = partseq as u64 * SLICE_SIZE;
            let byte_size = if partseq as u64 + 1 == count {
                last_block_size
            } else {
                SLICE_SIZE
            };
            let mut last_err = String::new();
            for attempt in 0..3u32 {
                if attempt > 0 {
                    tokio::time::sleep(Duration::from_secs(1 << (attempt - 1))).await;
                }
                match read_temp_part(tmp_path, offset, byte_size).await {
                    Ok(data) => {
                        match self
                            .upload_slice(path, uploadid, file_name, partseq, data)
                            .await
                        {
                            Ok(()) => {
                                last_err.clear();
                                break;
                            }
                            Err(e) => {
                                if e == ERR_UPLOADID_EXPIRED {
                                    return Err(e);
                                }
                                last_err = e;
                            }
                        }
                    }
                    Err(e) => last_err = e,
                }
            }
            if !last_err.is_empty() {
                return Err(last_err);
            }
            *slot = -1; // 对齐 Go：已传分片标记 -1
        }
        Ok(())
    }

    /// 对齐 Go 版 uploadSlice()：POST {upload_url}/rest/2.0/pcs/superfile2，
    /// multipart 手工拼装（head + 分片数据 + tail），query 带 method/access_token/
    /// type/path/uploadid/partseq，响应按 uploadid 失效 / error_code / errno 判定
    async fn upload_slice(
        &self,
        path: &str,
        uploadid: &str,
        file_name: &str,
        partseq: i64,
        data: Vec<u8>,
    ) -> Result<(), String> {
        let boundary = format!("openlistrs{}", Uuid::new_v4().simple());
        // 对齐 Go mw.CreateFormFile 的转义与固定 Content-Type
        let escaped = file_name.replace('\\', "\\\\").replace('"', "\\\"");
        let head = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{escaped}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        );
        let tail = format!("\r\n--{boundary}--\r\n");
        let mut body = Vec::with_capacity(head.len() + data.len() + tail.len());
        body.extend_from_slice(head.as_bytes());
        body.extend_from_slice(&data);
        body.extend_from_slice(tail.as_bytes());

        let params = [
            ("method".to_string(), "upload".to_string()),
            ("access_token".to_string(), self.access_token()),
            ("type".to_string(), "tmpfile".to_string()),
            ("path".to_string(), path.to_string()),
            ("uploadid".to_string(), uploadid.to_string()),
            ("partseq".to_string(), partseq.to_string()),
        ];
        let url = format!("{UPLOAD_API}/rest/2.0/pcs/superfile2");
        let resp = self
            .http
            .post(&url)
            .query(&params)
            .header(
                "Content-Type",
                format!("multipart/form-data; boundary={boundary}"),
            )
            .timeout(Duration::from_secs(UPLOAD_SLICE_TIMEOUT))
            .body(body)
            .send()
            .await
            .map_err(|e| format!("上传百度网盘分片失败: {e}"))?;
        let text = resp.text().await.unwrap_or_default();
        let lower = text.to_lowercase();
        // 对齐 Go：uploadid 失效检测
        if lower.contains("uploadid")
            && (lower.contains("invalid")
                || lower.contains("expired")
                || lower.contains("not found"))
        {
            return Err(ERR_UPLOADID_EXPIRED.to_string());
        }
        let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        let err_code = v.get("error_code").and_then(|x| x.as_i64()).unwrap_or(0);
        let errno = v.get("errno").and_then(|x| x.as_i64()).unwrap_or(0);
        if err_code != 0 || errno != 0 {
            return Err(format!("上传百度网盘分片失败，响应={}", trunc(&text, 200)));
        }
        Ok(())
    }
}

fn urlencode(s: &str) -> String {
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

// ---------- 写操作辅助 ----------

/// 根目录归一（对齐 list()："" / "0" -> "/"）
fn normalize_fid(fid: &str) -> &str {
    match fid {
        "" | "0" => "/",
        other => other,
    }
}

/// 路径拼接（对齐 Go stdpath.Join：百度 fid 即网盘绝对路径）
fn join_path(dir: &str, name: &str) -> String {
    let dir = dir.trim_end_matches('/');
    if dir.is_empty() {
        format!("/{name}")
    } else {
        format!("{dir}/{name}")
    }
}

/// 对齐 Go joinTime()：表单追加 local_ctime / local_mtime
fn join_time(form: &mut Vec<(String, String)>, ctime: i64, mtime: i64) {
    form.push(("local_mtime".to_string(), mtime.to_string()));
    form.push(("local_ctime".to_string(), ctime.to_string()));
}

/// 对齐 Go PrecreateResp 的 Rust 版最小集
struct PrecreateInfo {
    return_type: i64,
    uploadid: String,
    block_list: Vec<i64>,
}

/// 临时文件守卫：Drop 时必定删除临时文件（无论成功失败路径）
struct TempFileGuard(PathBuf);

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn temp_file_path() -> PathBuf {
    std::env::temp_dir().join(format!("openlist-rs-baidu-{}", Uuid::new_v4()))
}

/// 从临时文件按偏移读一段（分片上传用）
async fn read_temp_part(path: &Path, offset: u64, len: u64) -> Result<Vec<u8>, String> {
    let mut f = tokio::fs::File::open(path)
        .await
        .map_err(|e| format!("百度网盘打开临时文件失败: {e}"))?;
    f.seek(std::io::SeekFrom::Start(offset))
        .await
        .map_err(|e| format!("百度网盘临时文件 seek 失败: {e}"))?;
    let mut buf = vec![0u8; len as usize];
    f.read_exact(&mut buf)
        .await
        .map_err(|e| format!("百度网盘读取临时文件分片失败: {e}"))?;
    Ok(buf)
}

/// 落盘结果：总大小 + 整文件 md5 + 前 256KB md5 + 逐片（SLICE_SIZE）md5 列表
struct BaiduSpool {
    total: u64,
    file_md5: String,
    slice_md5: String,
    block_list: Vec<String>,
}

/// 把上传流落到临时文件，单趟边写边算全部 hash（对齐 Go Put 的 MultiWriter 三路 md5）：
/// - 整文件 md5（content-md5）
/// - 前 256KB md5（slice-md5，LimitWriter 语义）
/// - 每个 4MB 分片的 md5（block_list）
async fn spool_baidu(
    mut reader: std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send>>,
    path: &Path,
) -> Result<BaiduSpool, String> {
    let mut f = tokio::fs::File::create(path)
        .await
        .map_err(|e| format!("百度网盘创建临时文件失败: {e}"))?;
    let mut file_md5 = Md5::new();
    let mut slice_md5 = Md5::new();
    let mut slice_fed: u64 = 0;
    let mut block_md5 = Md5::new();
    let mut fed_in_block: u64 = 0;
    let mut block_list: Vec<String> = Vec::new();
    let mut total: u64 = 0;
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = reader
            .read(&mut buf)
            .await
            .map_err(|e| format!("百度网盘读取上传流失败: {e}"))?;
        if n == 0 {
            break;
        }
        f.write_all(&buf[..n])
            .await
            .map_err(|e| format!("百度网盘写入临时文件失败: {e}"))?;
        file_md5.update(&buf[..n]);
        // 前 256KB（对齐 Go LimitWriter）
        if slice_fed < SLICE_MD5_SIZE {
            let take = std::cmp::min(n as u64, SLICE_MD5_SIZE - slice_fed) as usize;
            slice_md5.update(&buf[..take]);
            slice_fed += take as u64;
        }
        // 逐片 md5（处理跨读块边界）
        let mut off = 0usize;
        while off < n {
            let in_block = total % SLICE_SIZE;
            let take = std::cmp::min((n - off) as u64, SLICE_SIZE - in_block) as usize;
            block_md5.update(&buf[off..off + take]);
            total += take as u64;
            off += take;
            fed_in_block += take as u64;
            if in_block + take as u64 == SLICE_SIZE {
                block_list.push(hex::encode(block_md5.finalize_reset()));
                fed_in_block = 0;
            }
        }
    }
    f.flush()
        .await
        .map_err(|e| format!("百度网盘临时文件落盘失败: {e}"))?;
    // 末尾不满一片的分片（对齐 Go lastBlockSize 语义）
    if fed_in_block > 0 {
        block_list.push(hex::encode(block_md5.finalize()));
    }
    Ok(BaiduSpool {
        total,
        file_md5: hex::encode(file_md5.finalize()),
        slice_md5: hex::encode(slice_md5.finalize()),
        block_list,
    })
}

/// 按字符截断，避免多字节字符串按字节切片 panic
fn trunc(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}
