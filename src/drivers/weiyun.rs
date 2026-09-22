//! 腾讯微云驱动（对齐 Go 版 drivers/weiyun + weiyunsdk-go 协议，浏览/下载/写操作）
//!
//! - 授权：www.weiyun.com 登录后的 cookie（支持 QQ / 微信登录）
//! - 协议：POST https://www.weiyun.com/webapp/json/{protocol}/{name}
//!   body = {"req_header": "<json 字符串>", "req_body": "<json 字符串>"}
//!   query = g_tk(wyctoken cookie) + cmd
//! - 列目录：weiyunQdisk / DiskDirList（cmd 2208，count 500 翻页）
//! - 下载：weiyunQdiskClient / DiskFileBatchDownload（cmd 2402），
//!   直链需附带 Set-Cookie 下发的下载 cookie，必须走后端代理
//! - 写操作：DiskDirCreate/DiskFileRename/DiskDirAttrModify/DiskDirFileBatchMove/
//!   DiskDirFileBatchDeleteEx（weiyunQdiskClient）；
//!   上传走 ftn_pre_upload + upload.weiyun.com 分片通道（weiyunsdk-go PreUpload 协议）

use super::DownloadInfo;
use crate::config::Entry;
use base64::Engine;
use reqwest::{Client, ClientBuilder, redirect};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use uuid::Uuid;

const BASE: &str = "https://www.weiyun.com";
const UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";
const TIMEOUT: Duration = Duration::from_secs(30);
/// cookie 过期错误标记（对齐 ErrCookieExpiration）
const EXPIRED: &str = "微云 cookie 已过期，请重新获取";
/// 上传预检查接口（对齐 SDK preUpload 协议）
const PRE_UPLOAD_URL: &str = "https://www.weiyun.com/api/v3/ftn_pre_upload";
/// 分片上传接口（对齐 SDK upload 协议）
const UPLOAD_URL: &str = "https://upload.weiyun.com/ftnup_v2/weiyun";
/// 分片上传 multipart 边界（对齐 SDK 固定边界）
const UPLOAD_BOUNDARY: &str = "----WebKitFormBoundaryIifrOqiswelC8nfe";
/// PreUpload / AddChannel / UploadPiece 的 cmd（对齐 weiyunsdk-go）
const CMD_PRE_UPLOAD: i64 = 247120;
const CMD_UPLOAD_PIECE: i64 = 247121;
const CMD_ADD_CHANNEL: i64 = 247122;
/// 上传块大小（对齐 SDK blockSize 1MB）
const UPLOAD_BLOCK_SIZE: u64 = 1024 * 1024;

pub struct Weiyun {
    http: Client,
    http_no_redirect: Client,
    cookies: Mutex<HashMap<String, String>>,
    cookie_order: Mutex<Vec<String>>,
    root_folder_id: String,
    /// 账号主目录 dir_key（懒加载）
    main_dir_key: Mutex<String>,
    /// 403 重试标记，防止无限循环
    refreshing: Mutex<bool>,
}

impl Weiyun {
    pub fn new(cookies: String, root_folder_id: String) -> Self {
        let (map, order) = parse_cookie_str(&cookies);
        Weiyun {
            http: Client::builder().timeout(TIMEOUT).build().unwrap(),
            http_no_redirect: ClientBuilder::new()
                .timeout(TIMEOUT)
                .redirect(redirect::Policy::none())
                .build()
                .unwrap(),
            cookies: Mutex::new(map),
            cookie_order: Mutex::new(order),
            root_folder_id,
            main_dir_key: Mutex::new(String::new()),
            refreshing: Mutex::new(false),
        }
    }

    fn cookie(&self, name: &str) -> String {
        self.cookies
            .lock()
            .unwrap()
            .get(name)
            .cloned()
            .unwrap_or_default()
    }

    fn cookie_header(&self) -> String {
        let map = self.cookies.lock().unwrap();
        let order = self.cookie_order.lock().unwrap();
        order
            .iter()
            .filter_map(|k| map.get(k).map(|v| format!("{k}={v}")))
            .collect::<Vec<_>>()
            .join("; ")
    }

    /// 对齐 Go 版 cookie jar：每次响应的 Set-Cookie 滚动并入 cookie 存储，
    /// 微云会经 Set-Cookie 轮换会话字段，丢弃会导致后续请求被网关拒绝
    fn store_cookies(&self, headers: &reqwest::header::HeaderMap) {
        let mut map = self.cookies.lock().unwrap();
        let mut order = self.cookie_order.lock().unwrap();
        for v in headers.get_all(reqwest::header::SET_COOKIE) {
            let Ok(s) = v.to_str() else { continue };
            // 只取第一个 k=v 对（忽略 Path/Domain/Expires 等属性）
            let Some(pair) = s.split(';').next() else { continue };
            let Some((k, val)) = pair.split_once('=') else { continue };
            let (k, val) = (k.trim(), val.trim());
            if k.is_empty() || val.is_empty() {
                continue;
            }
            if !map.contains_key(k) {
                order.push(k.to_string());
            }
            map.insert(k.to_string(), val.to_string());
        }
    }

    /// 对齐 LoginType()
    fn login_type(&self) -> &'static str {
        let wy_uf = self.cookie("wy_uf");
        if wy_uf == "2" {
            if !self.cookie("weiyun_wx_openid").is_empty() {
                return "weixin_openid";
            }
            if !self.cookie("weiyun_qq_openid").is_empty() {
                return "qq_openid";
            }
        }
        if wy_uf == "1" {
            return "weixin";
        }
        if wy_uf == "0" || wy_uf.is_empty() {
            return "qq";
        }
        "unknown"
    }

    /// 对齐 ParseTokenInfo()
    fn token_info(&self) -> Value {
        match self.login_type() {
            "weixin" => json!({
                "token_type": 1,
                "openid": self.cookie("openid"),
                "open_appid": self.cookie("wy_appid"),
                "access_token": self.cookie("access_token"),
                "login_key_type": 192,
                "login_key_value": self.cookie("access_token"),
            }),
            "weixin_openid" | "qq_openid" => json!({
                "token_type": 3,
                "login_key_type": 1540,
            }),
            "qq" => json!({
                "token_type": 0,
                "login_key_type": 27,
                "login_key_value": self.cookie("p_skey"),
                "openid": "",
            }),
            _ => json!({}),
        }
    }

    /// 对齐 RefreshCtoken()：GET /disk，发生 302 即 cookie 过期
    async fn refresh_ctoken(&self) -> Result<(), String> {
        let resp = self
            .http_no_redirect
            .get(format!("{BASE}/disk"))
            .header("user-agent", UA)
            .header("cookie", self.cookie_header())
            .send()
            .await
            .map_err(|e| format!("刷新微云会话失败: {e}"))?;
        self.store_cookies(resp.headers());
        if resp.status().is_redirection() || resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(EXPIRED.to_string());
        }
        Ok(())
    }

    /// 对齐 WeiXinRefreshToken()：微信登录 cookie 过期时刷 access_token，
    /// 依赖 cookie 中的 wy_appid / refresh_token，成功后回写 openid / access_token / refresh_token
    async fn weixin_refresh_token(&self) -> Result<(), String> {
        let (appid, rt) = (self.cookie("wy_appid"), self.cookie("refresh_token"));
        if appid.is_empty() || rt.is_empty() {
            return Err("微信刷新 token 缺少 wy_appid / refresh_token cookie".into());
        }
        let resp = self
            .http
            .get("https://api.weixin.qq.com/sns/oauth2/refresh_token")
            .query(&[
                ("grant_type", "refresh_token"),
                ("appid", appid.as_str()),
                ("refresh_token", rt.as_str()),
            ])
            .header("user-agent", UA)
            .send()
            .await
            .map_err(|e| format!("微信刷新 token 请求失败: {e}"))?;
        let v: Value = resp
            .json()
            .await
            .map_err(|e| format!("微信刷新 token 响应解析失败: {e}"))?;
        let errcode = v.get("errcode").and_then(|x| x.as_i64()).unwrap_or(0);
        if errcode != 0 {
            let errmsg = v
                .get("errmsg")
                .and_then(|x| x.as_str())
                .unwrap_or("unknown");
            return Err(format!("微信刷新 token 失败(errcode={errcode}): {errmsg}"));
        }
        // 对齐 SetCookieValue：回写 cookie 中的同名字段（无则新增）
        let mut map = self.cookies.lock().unwrap();
        let mut order = self.cookie_order.lock().unwrap();
        for key in ["openid", "access_token", "refresh_token"] {
            if let Some(nv) = v.get(key).and_then(|x| x.as_str()) {
                if nv.is_empty() {
                    continue;
                }
                if !map.contains_key(key) {
                    order.push(key.to_string());
                }
                map.insert(key.to_string(), nv.to_string());
            }
        }
        Ok(())
    }

    /// 对齐 request()（默认分支）：403 时刷新会话重试一次
    async fn request(
        &self,
        protocol: &str,
        cmd_name: &str,
        cmd: i64,
        data: Value,
    ) -> Result<Value, String> {
        let body = self.build_body(cmd_name, cmd, &data);
        let resp = self
            .do_request(protocol, cmd_name, cmd, &body)
            .await?;
        match resp {
            Ok(v) => Ok(v),
            Err(e) if e.contains("HTTP 403") => {
                // 单飞刷新后重试一次；微信登录先刷微信 token 再验证（对齐 Request() 403 分支）
                let should_refresh = {
                    let mut flag = self.refreshing.lock().unwrap();
                    if *flag {
                        false
                    } else {
                        *flag = true;
                        true
                    }
                };
                if !should_refresh {
                    return Err(e);
                }
                let r = match self.refresh_ctoken().await {
                    Err(e2) if e2 == EXPIRED
                        && matches!(self.login_type(), "weixin" | "weixin_openid") =>
                    {
                        match self.weixin_refresh_token().await {
                            Ok(()) => self.refresh_ctoken().await,
                            Err(e3) => Err(e3),
                        }
                    }
                    other => other,
                };
                *self.refreshing.lock().unwrap() = false;
                r?;
                let resp = self.do_request(protocol, cmd_name, cmd, &body).await?;
                resp
            }
            Err(e) => Err(e),
        }
    }

    fn build_body(&self, cmd_name: &str, cmd: i64, data: &Value) -> Value {
        let token_info = self.token_info();
        let wx_openid = token_info
            .get("openid")
            .and_then(|x| x.as_str())
            .unwrap_or("");
        let wx_openid = if wx_openid.is_empty() {
            token_info.get("minico_openid").cloned().unwrap_or(Value::Null)
        } else {
            json!(wx_openid)
        };
        let seq = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let req_header = json!({
            "seq": seq,
            "cmd": cmd,
            "wx_openid": wx_openid,
            "qq_openid": token_info.get("qq_openid").cloned().unwrap_or(Value::Null),
            "user_flag": token_info.get("token_type").cloned().unwrap_or(Value::Null),
            "env_id": token_info.get("env_id").cloned().unwrap_or(Value::Null),
            "type": 1,
            "appid": 30013,
            "version": 3,
            "major_version": 3,
            "minor_version": 3,
            "fix_version": 3,
        });
        let mut req_body = json!({
            "ReqMsg_body": {
                "ext_req_head": {
                    "token_info": token_info,
                    "language_info": { "language_type": 2052 },
                }
            }
        });
        // json! 宏的 key 需为字面量，动态 cmd_name 的字段运行时插入
        req_body["ReqMsg_body"][format!(".weiyun.{cmd_name}MsgReq_body").as_str()] = data.clone();
        json!({
            "req_header": serde_json::to_string(&req_header).unwrap_or_default(),
            "req_body": serde_json::to_string(&req_body).unwrap_or_default(),
        })
    }

    /// 发送请求并解析 Resp{ret,msg,data:{rsp_header,rsp_body}}
    async fn do_request(
        &self,
        protocol: &str,
        cmd_name: &str,
        cmd: i64,
        body: &Value,
    ) -> Result<Result<Value, String>, String> {
        let url = format!("{BASE}/webapp/json/{protocol}/{cmd_name}");
        let resp = self
            .http
            .post(&url)
            .query(&[
                ("g_tk", self.cookie("wyctoken")),
                ("cmd", cmd.to_string()),
            ])
            .header("user-agent", UA)
            .header("referer", format!("{BASE}/disk"))
            .header("origin", BASE)
            .header("content-type", "application/json")
            .header("cookie", self.cookie_header())
            .json(body)
            .send()
            .await
            .map_err(|e| format!("微云请求失败: {e}"))?;
        let status = resp.status().as_u16();
        self.store_cookies(resp.headers());
        let text = resp.text().await.map_err(|e| format!("读取响应失败: {e}"))?;
        if status != 200 {
            if status == 403 {
                return Ok(Err("HTTP 403（会话可能已过期）".into()));
            }
            return Err(format!(
                "微云服务器返回 HTTP {status}（{cmd_name}）: {}",
                trunc300(&text)
            ));
        }
        let v: Value = serde_json::from_str(&text)
            .map_err(|e| format!("微云响应解析失败: {e}: {}", trunc300(&text)))?;
        // 顶层 ret 字段缺失 = 成功（对齐 Go：json 反序列化缺省 0），
        // 实测 DiskUserInfoGet 响应只有 data.rsp_header.retcode，无顶层 ret
        let ret = v.get("ret").and_then(|x| x.as_i64()).unwrap_or(0);
        if ret != 0 {
            let msg = v
                .get("msg")
                .and_then(|x| x.as_str())
                .unwrap_or("unknown")
                .to_string();
            return Ok(Err(format!(
                "微云接口错误({cmd_name} ret={ret}): {msg}；响应: {}",
                trunc300(&text)
            )));
        }
        let retcode = v
            .pointer("/data/rsp_header/retcode")
            .and_then(|x| x.as_i64())
            .unwrap_or(0);
        if retcode != 0 {
            let msg = v
                .pointer("/data/rsp_header/retmsg")
                .and_then(|x| x.as_str())
                .unwrap_or("unknown")
                .to_string();
            return Ok(Err(format!(
                "微云接口错误({cmd_name} retcode={retcode}): {msg}"
            )));
        }
        let body = v
            .pointer("/data/rsp_body/RspMsg_body")
            .cloned()
            .unwrap_or(json!({}));
        Ok(Ok(body))
    }

    /// 根目录 dir_key：优先凭据里的 root_folder_id，否则账号主目录（懒加载）
    async fn root_dir_key(&self) -> Result<String, String> {
        if !self.root_folder_id.is_empty() {
            return Ok(self.root_folder_id.clone());
        }
        {
            let k = self.main_dir_key.lock().unwrap();
            if !k.is_empty() {
                return Ok(k.clone());
            }
        }
        let info = self.disk_user_info_get().await?;
        let key = info
            .get("main_dir_key")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if key.is_empty() {
            return Err("微云未获取到账号主目录".into());
        }
        *self.main_dir_key.lock().unwrap() = key.clone();
        Ok(key)
    }

    /// weiyunQdiskClient / DiskUserInfoGet（cmd 2201）
    async fn disk_user_info_get(&self) -> Result<Value, String> {
        let data = json!({
            "is_get_upload_flow_flag": false,
            "is_get_high_speed_flow_info": false,
            "is_get_weiyun_flag": false,
            "is_get_space_clean_info": false,
            "is_get_user_reward_info": false,
        });
        self.request("weiyunQdiskClient", "DiskUserInfoGet", 2201, data)
            .await
    }

    /// 对齐 Init()
    pub async fn validate(&self) -> Result<(), String> {
        if self.cookie_header().is_empty() {
            return Err("微云 cookies 不能为空".into());
        }
        self.refresh_ctoken().await?;
        self.disk_user_info_get().await?;
        // 预取主目录，失败即凭据无效
        self.root_dir_key().await?;
        Ok(())
    }

    /// 对齐 List()：DiskDirList（cmd 2208）count 500 翻页
    pub async fn list(&self, parent_fid: &str) -> Result<Vec<Entry>, String> {
        let dir_key = if parent_fid.is_empty() || parent_fid == "0" {
            self.root_dir_key().await?
        } else {
            parent_fid.to_string()
        };
        let mut out = Vec::new();
        let mut start: i64 = 0;
        loop {
            let data = json!({
                "dir_key": dir_key,
                "start": start,
                "count": 500,
                "sort_field": 2,
                "reverse_order": false,
                "get_type": 0,
                "get_abstract_url": false,
                "get_dir_detail_info": false,
            });
            let resp = self
                .request("weiyunQdisk", "DiskDirList", 2208, data)
                .await?;
            let dirs = resp
                .get("dir_list")
                .and_then(|x| x.as_array())
                .cloned()
                .unwrap_or_default();
            let files = resp
                .get("file_list")
                .and_then(|x| x.as_array())
                .cloned()
                .unwrap_or_default();
            let finish = resp
                .get("finish_flag")
                .and_then(|x| x.as_bool())
                .unwrap_or(true);
            for d in &dirs {
                out.push(Entry {
                    fid: d
                        .get("dir_key")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string(),
                    name: d
                        .get("dir_name")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string(),
                    size: 0,
                    is_dir: true,
                    updated_at: json_num_or_str_ms(d.get("dir_mtime")),
                    etag: None,
                    s3_key_flag: None,
                    file_type: None,
                    extra: None,
                });
            }
            for f in &files {
                // 文件下载需要父目录 dir_key，挂到 extra 透传
                let extra = json!({ "pdir_key": dir_key });
                out.push(Entry {
                    fid: f
                        .get("file_id")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string(),
                    name: f
                        .get("filename")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string(),
                    size: f.get("file_size").and_then(|x| x.as_u64()).unwrap_or(0),
                    is_dir: false,
                    updated_at: json_num_or_str_ms(f.get("file_mtime")),
                    etag: f
                        .get("file_sha")
                        .and_then(|x| x.as_str())
                        .map(|s| s.to_string()),
                    s3_key_flag: None,
                    file_type: None,
                    extra: Some(extra),
                });
            }
            start += (dirs.len() + files.len()) as i64;
            if finish || (dirs.is_empty() && files.is_empty()) {
                break;
            }
        }
        Ok(out)
    }

    /// 对齐 Link()：DiskFileBatchDownload（cmd 2402）
    pub async fn download(&self, e: &Entry) -> Result<DownloadInfo, String> {
        if e.is_dir {
            return Err("目录无法下载".into());
        }
        let pdir_key = e
            .extra
            .as_ref()
            .and_then(|x| x.get("pdir_key"))
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if pdir_key.is_empty() {
            return Err("微云缺少父目录信息（pdir_key）".into());
        }
        let data = json!({
            "file_list": [ { "pdir_key": pdir_key, "file_id": e.fid } ],
            "download_type": 0,
        });
        let resp = self
            .request("weiyunQdiskClient", "DiskFileBatchDownload", 2402, data)
            .await?;
        let item = resp
            .get("file_list")
            .and_then(|x| x.as_array())
            .and_then(|a| a.first())
            .cloned()
            .ok_or("微云未返回下载信息")?;
        let url = item
            .get("download_url")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if url.is_empty() {
            return Err("微云未取到下载直链".into());
        }
        let cookie = format!(
            "{}={}",
            item.get("cookie_name").and_then(|x| x.as_str()).unwrap_or(""),
            item.get("cookie_value").and_then(|x| x.as_str()).unwrap_or("")
        );
        Ok(DownloadInfo {
            url,
            headers: vec![("Cookie".into(), cookie)],
            proxy: true,
            local_path: None,
        })
    }

    // ---------- 写操作（对齐 Go 版 MakeDir/Rename/Move/Copy/Remove/Put） ----------

    /// 目录 fid 归一化：""/"0" -> 账号根目录 dir_key
    async fn dir_key_of(&self, fid: &str) -> Result<String, String> {
        if fid.is_empty() || fid == "0" {
            self.root_dir_key().await
        } else {
            Ok(fid.to_string())
        }
    }

    /// 查询目录的父目录 key（对齐 Go Init 用 LibDirPathGet 取 PdirKey 的做法）：
    /// weiyunFileLibClient / LibDirPathGet（cmd 26150），取链路最后一项的 pdir_key
    async fn pkey_of(&self, dir_key: &str) -> Result<String, String> {
        let resp = self
            .request(
                "weiyunFileLibClient",
                "LibDirPathGet",
                26150,
                json!({ "dir_key": dir_key }),
            )
            .await?;
        let items = resp
            .get("items")
            .and_then(|x| x.as_array())
            .cloned()
            .unwrap_or_default();
        let last = items
            .last()
            .ok_or_else(|| format!("微云未查询到目录路径信息(dir_key={dir_key})"))?;
        Ok(last
            .get("pdir_key")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string())
    }

    /// 对齐 MakeDir：DiskDirCreate（cmd 2614，同名自动重命名）
    pub async fn mkdir(&self, parent_fid: &str, name: &str) -> Result<(), String> {
        if name.is_empty() {
            return Err("目录名为空".into());
        }
        let dir_key = self.dir_key_of(parent_fid).await?;
        let ppdir_key = self.pkey_of(&dir_key).await?;
        let data = json!({
            "ppdir_key": ppdir_key,
            "pdir_key": dir_key,
            "dir_name": name,
            "file_exist_option": 2,
            "create_type": 1,
        });
        self.request("weiyunQdiskClient", "DiskDirCreate", 2614, data)
            .await?;
        Ok(())
    }

    /// 对齐 Rename：文件 DiskFileRename（cmd 2605）/ 目录 DiskDirAttrModify（cmd 2615）
    pub async fn rename(&self, parent_fid: &str, e: &Entry, new_name: &str) -> Result<(), String> {
        if new_name.is_empty() {
            return Err("新名称为空".into());
        }
        let dir_key = self.dir_key_of(parent_fid).await?;
        let ppdir_key = self.pkey_of(&dir_key).await?;
        let (cmd_name, cmd, data) = if e.is_dir {
            (
                "DiskDirAttrModify",
                2615,
                json!({
                    "ppdir_key": ppdir_key,
                    "pdir_key": dir_key,
                    "dir_key": e.fid,
                    "src_dir_name": e.name,
                    "dst_dir_name": new_name,
                }),
            )
        } else {
            (
                "DiskFileRename",
                2605,
                json!({
                    "ppdir_key": ppdir_key,
                    "pdir_key": dir_key,
                    "file_id": e.fid,
                    "src_filename": e.name,
                    "filename": new_name,
                }),
            )
        };
        self.request("weiyunQdiskClient", cmd_name, cmd, data).await?;
        Ok(())
    }

    /// 对齐 Move：文件/目录统一走 DiskDirFileBatchMove（cmd 2618）
    pub async fn move_entry(
        &self,
        parent_fid: &str,
        e: &Entry,
        dst_dir_fid: &str,
    ) -> Result<(), String> {
        let src_pdir = self.dir_key_of(parent_fid).await?;
        let src_ppdir = self.pkey_of(&src_pdir).await?;
        let dst_pdir = self.dir_key_of(dst_dir_fid).await?;
        let dst_ppdir = self.pkey_of(&dst_pdir).await?;
        let data = if e.is_dir {
            json!({
                "src_ppdir_key": src_ppdir,
                "src_pdir_key": src_pdir,
                "dir_list": [ {
                    "ppdir_key": src_ppdir,
                    "pdir_key": src_pdir,
                    "dir_key": e.fid,
                    "dir_name": e.name,
                } ],
                "dst_ppdir_key": dst_ppdir,
                "dst_pdir_key": dst_pdir,
            })
        } else {
            json!({
                "src_ppdir_key": src_ppdir,
                "src_pdir_key": src_pdir,
                "file_list": [ {
                    "ppdir_key": src_ppdir,
                    "pdir_key": src_pdir,
                    "file_id": e.fid,
                    "filename": e.name,
                } ],
                "dst_ppdir_key": dst_ppdir,
                "dst_pdir_key": dst_pdir,
            })
        };
        self.request("weiyunQdiskClient", "DiskDirFileBatchMove", 2618, data)
            .await?;
        Ok(())
    }

    /// 对齐 Copy（Go 版返回 errs.NotImplement）
    pub async fn copy(&self, _parent_fid: &str, _e: &Entry, _dst_dir_fid: &str) -> Result<(), String> {
        Err("微云不支持复制操作".into())
    }

    /// 对齐 Remove：DiskDirFileBatchDeleteEx（cmd 2509，文件/目录同一接口）
    pub async fn remove(&self, parent_fid: &str, e: &Entry) -> Result<(), String> {
        let dir_key = self.dir_key_of(parent_fid).await?;
        let ppdir_key = self.pkey_of(&dir_key).await?;
        let data = if e.is_dir {
            json!({
                "dir_list": [ {
                    "ppdir_key": ppdir_key,
                    "pdir_key": dir_key,
                    "dir_key": e.fid,
                    "dir_name": e.name,
                } ]
            })
        } else {
            json!({
                "file_list": [ {
                    "ppdir_key": ppdir_key,
                    "pdir_key": dir_key,
                    "file_id": e.fid,
                    "filename": e.name,
                } ]
            })
        };
        self.request("weiyunQdiskClient", "DiskDirFileBatchDeleteEx", 2509, data)
            .await?;
        Ok(())
    }

    /// 对齐 Put：PreUpload（sha1 秒传检测）-> AddUploadChannel -> 逐通道上传分片。
    /// 上传需要整文件 sha1 与末块校验数据，reader 不可回放，先落临时文件再上传（finally 删除）
    pub async fn put(&self, dst_dir_fid: &str, input: super::PutInput) -> Result<(), String> {
        let dir_key = self.dir_key_of(dst_dir_fid).await?;
        let ppdir_key = self.pkey_of(&dir_key).await?;
        let tmp_path = temp_file_path();
        let _guard = TempFileGuard(tmp_path.clone());
        let size = spool_to_temp(input.reader, &tmp_path).await?;
        // file_sha 已作为末块条目包含在 block_info_list 中
        let (block_info_list, check_sha, check_data, _file_sha) =
            compute_upload_hashes(&tmp_path, size).await?;

        // step 1. PreUpload（对齐 SDK PreUpload：block_size 1MB，末块 sha 校验，4 通道）
        let param = json!({
            "common_upload_req": {
                "ppdir_key": ppdir_key,
                "pdir_key": dir_key,
                "file_size": size as i64,
                "filename": input.name,
                "file_exist_option": 1,
                "use_mutil_channel": true,
            },
            "upload_scr": 0,
            "channel_count": 4,
            "block_size": UPLOAD_BLOCK_SIZE as i64,
            "check_sha": check_sha,
            "check_data": check_data,
            "block_info_list": block_info_list,
        });
        let pre = self.pre_upload(param).await?;
        // 秒传命中（对齐 preData.FileExist）
        if pre
            .get("file_exist")
            .and_then(|x| x.as_bool())
            .unwrap_or(false)
        {
            return Ok(());
        }
        let upload_key = pre
            .get("upload_key")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let ex = pre
            .get("ex")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let mut channels: Vec<(i64, i64, i64)> = pre
            .get("channel_list")
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .map(|c| {
                        (
                            c.get("id").and_then(|x| x.as_i64()).unwrap_or(0),
                            c.get("offset").and_then(|x| x.as_i64()).unwrap_or(0),
                            c.get("len").and_then(|x| x.as_i64()).unwrap_or(0),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        if size > 0 && channels.is_empty() {
            return Err("微云 PreUpload 未返回上传通道".into());
        }

        // 上传接口不能复用 30s 超时的常规客户端，单独构建无超时客户端
        let up_http = Client::builder()
            .build()
            .map_err(|e| format!("构建微云上传客户端失败: {e}"))?;

        // step 2. 上传通道补足到 4 个（对齐 Go 默认 uploadThread=4）
        if (channels.len() as i64) < 4 {
            let added = self
                .add_upload_channel(&up_http, &upload_key, &ex, channels.len() as i64, 4)
                .await?;
            channels.extend(added);
        }

        // step 3. 逐通道上传分片（upload_state: 1=未完成 2=完成 3=本通道无剩余分片）
        for ch in channels {
            let mut channel = ch;
            loop {
                // 对齐 Go：channel.Len = min(fileSize-offset, channel.Len)
                let avail = size.saturating_sub(channel.1 as u64);
                let len = std::cmp::min(avail, channel.2 as u64);
                if len == 0 {
                    break;
                }
                let mut last_err = String::new();
                let mut next_state: Option<((i64, i64, i64), i64)> = None;
                for attempt in 0..3 {
                    if attempt > 0 {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                    let piece = match read_temp_part(&tmp_path, channel.1 as u64, len).await {
                        Ok(p) => p,
                        Err(e) => {
                            last_err = e;
                            continue;
                        }
                    };
                    match self
                        .upload_piece(&up_http, &upload_key, &ex, channel, &piece)
                        .await
                    {
                        Ok(r) => {
                            next_state = Some(r);
                            break;
                        }
                        Err(e) => last_err = e,
                    }
                }
                let (next, state) = next_state.ok_or(last_err)?;
                if state == 1 {
                    channel = next;
                } else {
                    break;
                }
            }
        }
        Ok(())
    }

    /// 403 后刷新会话（对齐 SDK Request 的 cookie 过期处理：微信登录先刷微信 token）
    async fn refresh_session(&self) -> Result<(), String> {
        let r = match self.refresh_ctoken().await {
            Err(e) if e == EXPIRED && matches!(self.login_type(), "weixin" | "weixin_openid") => {
                match self.weixin_refresh_token().await {
                    Ok(()) => self.refresh_ctoken().await,
                    Err(e3) => Err(e3),
                }
            }
            other => other,
        };
        r
    }

    /// 上传类请求公共封装（ftn_pre_upload / upload.weiyun.com）：
    /// query 带 g_tk + cmd，cookie/UA/referer/origin 与 webapp 接口一致；
    /// 403 时刷新会话重试一次，返回解析后的 JSON
    async fn upload_http(
        &self,
        client: &Client,
        url: &str,
        cmd: i64,
        body: Vec<u8>,
        content_type: &str,
    ) -> Result<Value, String> {
        for attempt in 0..2 {
            let resp = client
                .post(url)
                .query(&[
                    ("g_tk", self.cookie("wyctoken")),
                    ("cmd", cmd.to_string()),
                ])
                .header("user-agent", UA)
                .header("referer", format!("{BASE}/disk"))
                .header("origin", BASE)
                .header("content-type", content_type)
                .header("cookie", self.cookie_header())
                .body(body.clone())
                .send()
                .await
                .map_err(|e| format!("微云上传请求失败: {e}"))?;
            let status = resp.status().as_u16();
            self.store_cookies(resp.headers());
            let text = resp
                .text()
                .await
                .map_err(|e| format!("读取上传响应失败: {e}"))?;
            if status == 403 && attempt == 0 {
                self.refresh_session().await?;
                continue;
            }
            if status != 200 {
                return Err(format!(
                    "微云上传接口返回 HTTP {status}: {}",
                    trunc300(&text)
                ));
            }
            let v: Value = serde_json::from_str(&text)
                .map_err(|e| format!("微云上传响应解析失败: {e}: {}", trunc300(&text)))?;
            return Ok(v);
        }
        Err("微云上传请求失败（会话刷新后仍被拒绝）".into())
    }

    /// PreUpload：POST ftn_pre_upload，req_header/req_body 为 JSON 对象（对齐 SDK NewUploadJson），
    /// 响应取 weiyunPreUploadMsgRsp_body
    async fn pre_upload(&self, param: Value) -> Result<Value, String> {
        let body = json!({
            "req_header": {
                "cmd": CMD_PRE_UPLOAD,
                "appid": 30013,
                "major_version": 3,
                "minor_version": 0,
                "fix_version": 0,
                "version": 3,
                "user_flag": 0,
            },
            "req_body": {
                "ReqMsg_body": { "weiyun.PreUploadMsgReq_body": param }
            },
        });
        let bytes = serde_json::to_vec(&body).map_err(|e| format!("序列化 PreUpload 请求失败: {e}"))?;
        let client = Client::builder()
            .build()
            .map_err(|e| format!("构建微云上传客户端失败: {e}"))?;
        let v = self
            .upload_http(&client, PRE_UPLOAD_URL, CMD_PRE_UPLOAD, bytes, "application/json")
            .await?;
        // 响应形如 {ret, msg, result:{rsp_header:{retcode,retmsg}, rsp_body:{RspMsg_body:{...}}}}
        let ret = v.get("ret").and_then(|x| x.as_i64()).unwrap_or(0);
        if ret != 0 {
            let msg = v
                .get("msg")
                .and_then(|x| x.as_str())
                .unwrap_or("unknown")
                .to_string();
            return Err(format!("微云 PreUpload 失败(ret={ret}): {msg}"));
        }
        let retcode = v
            .pointer("/result/rsp_header/retcode")
            .or_else(|| v.pointer("/data/rsp_header/retcode"))
            .and_then(|x| x.as_i64())
            .unwrap_or(0);
        if retcode != 0 {
            let msg = v
                .pointer("/result/rsp_header/retmsg")
                .or_else(|| v.pointer("/data/rsp_header/retmsg"))
                .and_then(|x| x.as_str())
                .unwrap_or("unknown")
                .to_string();
            return Err(format!("微云 PreUpload 失败(retcode={retcode}): {msg}"));
        }
        Ok(v
            .pointer("/result/rsp_body/RspMsg_body/weiyunPreUploadMsgRsp_body")
            .or_else(|| v.pointer("/data/rsp_body/RspMsg_body/weiyunPreUploadMsgRsp_body"))
            .cloned()
            .unwrap_or(json!({})))
    }

    /// upload.weiyun.com multipart 请求（对齐 SDK：json 字段 + 可选 upload 文件分片，
    /// 固定边界与严格字节顺序），返回 weiyun.{cmdName}MsgRsp_body
    async fn upload_multipart(
        &self,
        client: &Client,
        cmd_name: &str,
        cmd: i64,
        data: Value,
        piece: Option<Vec<u8>>,
    ) -> Result<Value, String> {
        let mut req_body = json!({ "ReqMsg_body": {} });
        req_body["ReqMsg_body"][format!("weiyun.{cmd_name}MsgReq_body").as_str()] = data;
        let inner = json!({
            "req_header": {
                "cmd": cmd,
                "appid": 30013,
                "major_version": 3,
                "minor_version": 0,
                "fix_version": 0,
                "version": 3,
                "user_flag": 0,
            },
            "req_body": req_body,
        });
        let inner_str =
            serde_json::to_string(&inner).map_err(|e| format!("序列化上传请求失败: {e}"))?;
        // 严格按 SDK 字节格式拼装 multipart
        let mut body: Vec<u8> = Vec::with_capacity(inner_str.len() + piece.as_ref().map_or(0, |p| p.len()) + 512);
        body.extend_from_slice(
            format!(
                "--{UPLOAD_BOUNDARY}\r\nContent-Disposition: form-data; name=\"json\"\r\n\r\n{inner_str}"
            )
            .as_bytes(),
        );
        if let Some(p) = &piece {
            body.extend_from_slice(
                format!(
                    "\r\n--{UPLOAD_BOUNDARY}\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"blob\"\r\nContent-Type: application/octet-stream\r\n\r\n"
                )
                .as_bytes(),
            );
            body.extend_from_slice(p);
        }
        body.extend_from_slice(format!("\r\n--{UPLOAD_BOUNDARY}--\r\n").as_bytes());

        let ct = format!("multipart/form-data; boundary={UPLOAD_BOUNDARY}");
        let v = self
            .upload_http(client, UPLOAD_URL, cmd, body, &ct)
            .await?;
        // 响应直接绑定 rsp_header/rsp_body（对齐 SDK SetResult(&respRaw.Data)）；
        // 兼容 {data:{...}} 包装
        let retcode = v
            .pointer("/rsp_header/retcode")
            .or_else(|| v.pointer("/data/rsp_header/retcode"))
            .and_then(|x| x.as_i64())
            .unwrap_or(0);
        if retcode != 0 {
            let msg = v
                .pointer("/rsp_header/retmsg")
                .or_else(|| v.pointer("/data/rsp_header/retmsg"))
                .and_then(|x| x.as_str())
                .unwrap_or("unknown")
                .to_string();
            return Err(format!("微云上传接口错误({cmd_name} retcode={retcode}): {msg}"));
        }
        let body_key = format!("/rsp_body/RspMsg_body/weiyun.{cmd_name}MsgRsp_body");
        let body_key_data = format!("/data/rsp_body/RspMsg_body/weiyun.{cmd_name}MsgRsp_body");
        Ok(v
            .pointer(&body_key)
            .or_else(|| v.pointer(&body_key_data))
            .cloned()
            .unwrap_or(json!({})))
    }

    /// 增加上传通道（对齐 SDK AddUploadChannel，cmd 247122）
    async fn add_upload_channel(
        &self,
        client: &Client,
        upload_key: &str,
        ex: &str,
        orig: i64,
        dest: i64,
    ) -> Result<Vec<(i64, i64, i64)>, String> {
        let data = json!({
            "upload_key": upload_key,
            "ex": ex,
            "orig_channel_count": orig,
            "dest_channel_count": dest,
            "speed": 4303,
        });
        let resp = self
            .upload_multipart(client, "AddChannel", CMD_ADD_CHANNEL, data, None)
            .await?;
        Ok(resp
            .get("channels")
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .map(|c| {
                        (
                            c.get("id").and_then(|x| x.as_i64()).unwrap_or(0),
                            c.get("offset").and_then(|x| x.as_i64()).unwrap_or(0),
                            c.get("len").and_then(|x| x.as_i64()).unwrap_or(0),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    /// 上传一个分片（cmd 247121），返回 (下一分片 channel, upload_state)；
    /// 对齐 SDK：未完成且下一分片长度为 0 时沿用当前分片长度
    async fn upload_piece(
        &self,
        client: &Client,
        upload_key: &str,
        ex: &str,
        channel: (i64, i64, i64),
        piece: &[u8],
    ) -> Result<((i64, i64, i64), i64), String> {
        let (id, offset, len) = channel;
        let data = json!({
            "upload_key": upload_key,
            "ex": ex,
            "channel": { "id": id, "offset": offset, "len": len },
        });
        let resp = self
            .upload_multipart(client, "UploadPiece", CMD_UPLOAD_PIECE, data, Some(piece.to_vec()))
            .await?;
        let state = resp
            .get("upload_state")
            .and_then(|x| x.as_i64())
            .unwrap_or(0);
        let ch = resp.get("channel").cloned().unwrap_or(json!({}));
        let nid = ch.get("id").and_then(|x| x.as_i64()).unwrap_or(id);
        let noff = ch.get("offset").and_then(|x| x.as_i64()).unwrap_or(offset);
        let mut nlen = ch.get("len").and_then(|x| x.as_i64()).unwrap_or(0);
        if nlen == 0 && state == 1 {
            nlen = len;
        }
        Ok(((nid, noff, nlen), state))
    }
}

/// 微云的 mtime 可能是数字或数字字符串，统一解析为毫秒
fn json_num_or_str_ms(v: Option<&Value>) -> Option<i64> {
    match v? {
        Value::Number(n) => n.as_i64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

/// 错误信息里附带的原始响应片段（按字符截断，避免 UTF-8 边界 panic）
fn trunc300(s: &str) -> String {
    s.chars().take(300).collect()
}

/// 解析 "k=v; k2=v2" cookie 串（保留顺序，去重取后值）
fn parse_cookie_str(s: &str) -> (HashMap<String, String>, Vec<String>) {
    let mut map = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    for part in s.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let Some((k, v)) = part.split_once('=') else {
            continue;
        };
        let k = k.trim().to_string();
        let v = v.trim().to_string();
        // 对齐 ClearCookie：去空值
        if k.is_empty() || v.is_empty() {
            continue;
        }
        if !map.contains_key(&k) {
            order.push(k.clone());
        }
        map.insert(k, v);
    }
    (map, order)
}

// ---------- 上传辅助：临时文件落盘 / 分块 sha1 ----------

/// 临时文件守卫：Drop 时必定删除临时文件（无论成功失败路径）
struct TempFileGuard(PathBuf);

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn temp_file_path() -> PathBuf {
    std::env::temp_dir().join(format!("openlist-rs-weiyun-{}", Uuid::new_v4()))
}

/// 把上传流落到临时文件并返回实际大小
async fn spool_to_temp(
    mut reader: Pin<Box<dyn AsyncRead + Send>>,
    path: &Path,
) -> Result<u64, String> {
    let mut f = tokio::fs::File::create(path)
        .await
        .map_err(|e| format!("微云创建临时文件失败: {e}"))?;
    let mut buf = vec![0u8; 256 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = reader
            .read(&mut buf)
            .await
            .map_err(|e| format!("微云读取上传流失败: {e}"))?;
        if n == 0 {
            break;
        }
        f.write_all(&buf[..n])
            .await
            .map_err(|e| format!("微云写入临时文件失败: {e}"))?;
        total += n as u64;
    }
    f.flush()
        .await
        .map_err(|e| format!("微云临时文件落盘失败: {e}"))?;
    Ok(total)
}

/// 从临时文件读取 [offset, offset+len) 分片
async fn read_temp_part(path: &Path, offset: u64, len: u64) -> Result<Vec<u8>, String> {
    let mut f = tokio::fs::File::open(path)
        .await
        .map_err(|e| format!("微云打开临时文件失败: {e}"))?;
    f.seek(std::io::SeekFrom::Start(offset))
        .await
        .map_err(|e| format!("微云定位临时文件失败: {e}"))?;
    let mut buf = vec![0u8; len as usize];
    if len > 0 {
        f.read_exact(&mut buf)
            .await
            .map_err(|e| format!("微云读取临时文件分片失败: {e}"))?;
    }
    Ok(buf)
}

/// 计算 PreUpload 所需哈希（对齐 weiyunsdk-go PreUpload）：
/// - block_info_list：每个 1MB 块边界处的累积 sha1（hex），末项为整文件 sha1
/// - check_sha：读完除末块校验数据之外全部字节的 sha1 中间状态（hex）
/// - check_data：末块校验数据（末块大小 %128，为 0 取 128 字节）的 base64
///   服务器校验逻辑：sha1(check_sha 状态 || check_data) == 整文件 sha1
async fn compute_upload_hashes(
    path: &Path,
    size: u64,
) -> Result<(Vec<Value>, String, String, String), String> {
    let block = UPLOAD_BLOCK_SIZE;
    // 对齐 Go：lastBlockSize = size % block（整除时取 block）；size=0 时保持 0
    let mut last = size % block;
    if size > 0 && last == 0 {
        last = block;
    }
    let mut check = last % 128;
    if size > 0 && check == 0 {
        check = 128;
    }
    let before = size - last;

    let mut f = tokio::fs::File::open(path)
        .await
        .map_err(|e| format!("微云打开临时文件失败: {e}"))?;
    let mut hasher = Sha1::new();
    let mut block_info_list: Vec<Value> = Vec::new();
    let mut buf = vec![0u8; block as usize];
    let mut offset: u64 = 0;
    while offset < before {
        f.read_exact(&mut buf)
            .await
            .map_err(|e| format!("微云读取临时文件失败: {e}"))?;
        hasher.update(&buf);
        block_info_list.push(json!({
            "sha": hasher.state_hex(),
            "offset": offset as i64,
            "size": block as i64,
        }));
        offset += block;
    }
    // 末块去掉校验数据部分
    let mid = (last - check) as usize;
    if mid > 0 {
        let mut tail = vec![0u8; mid];
        f.read_exact(&mut tail)
            .await
            .map_err(|e| format!("微云读取临时文件失败: {e}"))?;
        hasher.update(&tail);
    }
    let check_sha = hasher.state_hex();
    // 校验数据（参与整文件 sha1）
    let mut cbuf = vec![0u8; check as usize];
    if check > 0 {
        f.read_exact(&mut cbuf)
            .await
            .map_err(|e| format!("微云读取临时文件失败: {e}"))?;
        hasher.update(&cbuf);
    }
    let check_data = base64::engine::general_purpose::STANDARD.encode(&cbuf);
    let file_sha = hasher.finish_hex();
    // 末块条目：sha 为整文件 sha1（对齐 Go 追加逻辑，size=0 时也追加 size=0 的条目）
    block_info_list.push(json!({
        "sha": file_sha,
        "offset": before as i64,
        "size": last as i64,
    }));
    Ok((block_info_list, check_sha, check_data, file_sha))
}

/// SHA-1 增量实现：需要在 1MB 块边界快照中间状态（sha1 crate 不暴露内部状态，
/// 对齐 Go GetSha1State 的累积哈希语义，手动实现标准算法）
#[derive(Clone)]
struct Sha1 {
    h: [u32; 5],
    buf: [u8; 64],
    buflen: usize,
    total: u64,
}

impl Sha1 {
    fn new() -> Self {
        Sha1 {
            h: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
            buf: [0; 64],
            buflen: 0,
            total: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total += data.len() as u64;
        if self.buflen > 0 {
            let take = std::cmp::min(64 - self.buflen, data.len());
            self.buf[self.buflen..self.buflen + take].copy_from_slice(&data[..take]);
            self.buflen += take;
            data = &data[take..];
            if self.buflen == 64 {
                let block = self.buf;
                Self::compress(&mut self.h, &block);
                self.buflen = 0;
            }
        }
        while data.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[..64]);
            Self::compress(&mut self.h, &block);
            data = &data[64..];
        }
        // 剩余不足 64 字节：追加到缓冲区尾部（此时 buflen 必为 0 或 data 为空）
        self.buf[self.buflen..self.buflen + data.len()].copy_from_slice(data);
        self.buflen += data.len();
    }

    /// 当前中间状态的十六进制摘要（20 字节大端，即标准 sha1 前缀哈希）
    fn state_hex(&self) -> String {
        self.h.iter().map(|x| format!("{x:08x}")).collect()
    }

    /// 补位后的最终摘要（不改变自身状态）
    fn finish_hex(&self) -> String {
        let mut s = self.clone();
        let bitlen = s.total.wrapping_mul(8);
        let mut tail = vec![0x80u8];
        while (s.buflen + tail.len()) % 64 != 56 {
            tail.push(0);
        }
        tail.extend_from_slice(&bitlen.to_be_bytes());
        // 补位不改变已计入的字节数
        let total = s.total;
        s.update(&tail);
        s.total = total;
        s.state_hex()
    }

    fn compress(h: &mut [u32; 5], block: &[u8; 64]) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[4 * i],
                block[4 * i + 1],
                block[4 * i + 2],
                block[4 * i + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, w_i) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let tmp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*w_i);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cookie() {
        let (map, order) = parse_cookie_str("a=1; b=2; a=3; ; c=");
        assert_eq!(map.get("a").unwrap(), "3");
        assert_eq!(map.get("b").unwrap(), "2");
        assert!(!map.contains_key("c"));
        assert_eq!(order, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn test_token_info_qq() {
        let w = Weiyun::new("wy_uf=0; p_skey=abc; wyctoken=tk".into(), String::new());
        assert_eq!(w.login_type(), "qq");
        let ti = w.token_info();
        assert_eq!(ti["token_type"], 0);
        assert_eq!(ti["login_key_value"], "abc");
        assert_eq!(w.cookie("wyctoken"), "tk");
    }

    #[test]
    fn test_token_info_weixin() {
        let w = Weiyun::new("wy_uf=1; openid=o1; wy_appid=ap; access_token=at".into(), String::new());
        assert_eq!(w.login_type(), "weixin");
        let ti = w.token_info();
        assert_eq!(ti["token_type"], 1);
        assert_eq!(ti["openid"], "o1");
    }

    #[test]
    fn test_build_body() {
        let w = Weiyun::new("wy_uf=0; p_skey=abc; wyctoken=tk".into(), String::new());
        let body = w.build_body("DiskDirList", 2208, &json!({"dir_key": "x"}));
        let header: Value =
            serde_json::from_str(body["req_header"].as_str().unwrap()).unwrap();
        assert_eq!(header["cmd"], 2208);
        assert_eq!(header["appid"], 30013);
        let inner: Value =
            serde_json::from_str(body["req_body"].as_str().unwrap()).unwrap();
        assert_eq!(
            inner["ReqMsg_body"][".weiyun.DiskDirListMsgReq_body"]["dir_key"],
            "x"
        );
    }

    #[test]
    fn test_sha1() {
        // 标准测试向量
        let mut h = Sha1::new();
        h.update(b"abc");
        assert_eq!(h.finish_hex(), "a9993e364706816aba3e25717850c26c9cd0d89d");
        let h0 = Sha1::new();
        assert_eq!(h0.finish_hex(), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        // 中间状态快照：前缀快照 + 剩余 == 整体一次算完（PreUpload 块哈希依赖此语义）
        let mut a = Sha1::new();
        a.update(b"hello ");
        let snap = a.clone();
        a.update(b"world");
        let mut b = Sha1::new();
        b.update(b"hello world");
        assert_eq!(a.finish_hex(), b.finish_hex());
        let mut s = snap;
        s.update(b"world");
        assert_eq!(s.finish_hex(), b.finish_hex());
    }
}
