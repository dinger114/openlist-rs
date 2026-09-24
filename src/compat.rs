use crate::api::{proxy_stream, sort_entries};
use crate::config::{Account, Entry};
use crate::drivers::PutInput;
use crate::sign;
use crate::state::AppState;
use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Json,
};
use futures_util::TryStreamExt;
use serde::Deserialize;
use serde_json::{json, Value};
use std::io::Error as IoError;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio_util::io::StreamReader;

/// 把流式 body 的错误统一转成 io::Error（StreamReader 的 bound 要求）
fn io_err(e: impl std::fmt::Display) -> IoError {
    IoError::other(e.to_string())
}

// ============================================================
// OpenList 官方 API 兼容层（AList 协议，供 NovaTV / TVBox 等客户端）
// 响应统一 HTTP 200 + {"code":..,"message":..,"data":..}
// 路径方案：根目录下为各账号文件夹（账号备注名），进入即浏览对应网盘
// ============================================================

// 对齐 OpenList internal/conf: UNKNOWN=0 FOLDER=1 VIDEO=2 AUDIO=3 TEXT=4 IMAGE=5
const T_UNKNOWN: i64 = 0;
const T_FOLDER: i64 = 1;
const T_VIDEO: i64 = 2;
const T_AUDIO: i64 = 3;
const T_TEXT: i64 = 4;
const T_IMAGE: i64 = 5;
// 对齐 internal/bootstrap/data/setting.go 默认扩展名
const VIDEO_EXTS: &[&str] = &["mp4", "mkv", "avi", "mov", "rmvb", "webm", "flv", "m3u8"];
const AUDIO_EXTS: &[&str] = &["mp3", "flac", "ogg", "m4a", "wav", "opus", "wma"];
const IMAGE_EXTS: &[&str] = &[
    "jpg", "tiff", "jpeg", "png", "gif", "bmp", "svg", "ico", "swf", "webp", "avif",
];
const TEXT_EXTS: &str = "txt,htm,html,xml,java,properties,sql,js,md,json,conf,ini,vue,php,py,bat,gitignore,css,go,csv,c,h,sh,vtt,srt,ass,ssa";

fn obj_type(name: &str, is_dir: bool) -> i64 {
    if is_dir {
        return T_FOLDER;
    }
    let ext = name.rsplit('.').next().unwrap_or("").to_lowercase();
    if VIDEO_EXTS.contains(&ext.as_str()) {
        return T_VIDEO;
    }
    if AUDIO_EXTS.contains(&ext.as_str()) {
        return T_AUDIO;
    }
    if IMAGE_EXTS.contains(&ext.as_str()) {
        return T_IMAGE;
    }
    if TEXT_EXTS.split(',').any(|e| e == ext) {
        return T_TEXT;
    }
    T_UNKNOWN
}

fn normalize_path(p: &str) -> String {
    let mut s = p.trim().to_string();
    if !s.starts_with('/') {
        s.insert(0, '/');
    }
    while s.len() > 1 && s.ends_with('/') {
        s.pop();
    }
    s
}

/// 对齐 Go utils.EncodePath: 按段百分号编码，保留 /
fn path_encode(p: &str) -> String {
    p.split('/')
        .map(|seg| {
            let mut out = String::new();
            for b in seg.bytes() {
                match b {
                    b'A'..=b'Z'
                    | b'a'..=b'z'
                    | b'0'..=b'9'
                    | b'-'
                    | b'_'
                    | b'.'
                    | b'~'
                    | b'@'
                    | b'!'
                    | b'('
                    | b')'
                    | b'\''
                    | b'*' => out.push(b as char),
                    _ => out.push_str(&format!("%{b:02X}")),
                }
            }
            out
        })
        .collect::<Vec<_>>()
        .join("/")
}

// 日期换算统一走 drivers/timeutil（原为本地副本）
use crate::drivers::timeutil::civil_from_days;

/// unix 毫秒 -> RFC3339（东八区），对齐 Go time.Time JSON 格式
fn rfc3339_cst(ms: i64) -> String {
    let secs = (ms / 1000) + 8 * 3600;
    let rem = (secs as u64) % 86400;
    let days = secs.div_euclid(86400);
    let hour = rem / 3600;
    let min = (rem % 3600) / 60;
    let sec = rem % 60;
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}T{hour:02}:{min:02}:{sec:02}+08:00")
}

/// 拼接父路径与子项名（对齐 Go `stdpath.Join`，父路径已规范化、名字不含 '/'）
fn join_path(parent: &str, name: &str) -> String {
    if parent.ends_with('/') {
        format!("{parent}{name}")
    } else {
        format!("{parent}/{name}")
    }
}

/// 对象 JSON。`path` 是该对象的完整路径，用于生成 `sign` 字段：
/// 目录留空（对齐 Go `common.Sign`），文件给出链接签名，客户端可直接拼 /d、/p 链接。
fn obj_resp_json(e: &Entry, path: &str, secret: &[u8]) -> Value {
    let modified = e.updated_at.map(rfc3339_cst);
    let sign_val = if e.is_dir {
        String::new()
    } else {
        sign::sign(path, 0, secret)
    };
    json!({
        "name": e.name,
        "size": e.size,
        "is_dir": e.is_dir,
        "modified": modified,
        "created": modified,
        "sign": sign_val,
        "thumb": "",
        "type": obj_type(&e.name, e.is_dir),
        "hashinfo": "",
        "hash_info": null,
    })
}

fn compat_err(msg: impl Into<String>, code: i64) -> Response {
    (
        StatusCode::OK,
        Json(json!({ "code": code, "message": msg.into(), "data": null })),
    )
        .into_response()
}

// ---------- 路径索引（AppState 的兼容层方法） ----------

impl AppState {
    /// 把目录 children 注册到路径索引
    fn index_children(&self, parent: &str, account_id: &str, children: &[Entry]) {
        let mut idx = self.index.lock().unwrap();
        for c in children {
            let key = format!("{parent}/{}", c.name);
            idx.insert(key, (account_id.to_string(), c.clone()));
        }
    }

    /// 解析路径 -> (account_id, Entry)。索引未命中时逐级向下走并注册。
    pub(crate) async fn resolve_path(&self, path: &str) -> Result<(String, Entry), String> {
        let path = normalize_path(path);
        let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if segs.is_empty() {
            return Err("根目录没有对应文件".into());
        }
        // 第一段 = 账号名
        let accounts: Vec<Account> = self.store.data.lock().unwrap().accounts.clone();
        let Some(acc) = accounts.iter().find(|a| a.name == segs[0]) else {
            return Err(format!("找不到网盘账号: {}", segs[0]));
        };
        let acc_id = acc.id.clone();
        let mut entry = Entry {
            fid: acc.root_fid.clone(),
            name: segs[0].to_string(),
            is_dir: true,
            ..Default::default()
        };
        {
            let mut idx = self.index.lock().unwrap();
            idx.insert(format!("/{}", segs[0]), (acc_id.clone(), entry.clone()));
        }
        let mut prefix = format!("/{}", segs[0]);
        for seg in &segs[1..] {
            if !entry.is_dir {
                return Err(format!("路径不存在: {prefix}/{seg}"));
            }
            let full = format!("{prefix}/{seg}");
            // 索引命中直接复用
            if let Some(hit) = self.index.lock().unwrap().get(&full).cloned() {
                prefix = full;
                entry = hit.1;
                continue;
            }
            // 未命中：列出父目录并注册
            let driver = self.get_driver(&acc_id).await?;
            let children = driver.list(&entry.fid).await?;
            self.index_children(&prefix, &acc_id, &children);
            let hit = self.index.lock().unwrap().get(&full).cloned();
            let Some(hit) = hit else {
                return Err(format!("路径不存在: {full}"));
            };
            prefix = full;
            entry = hit.1;
        }
        Ok((acc_id, entry))
    }

    /// 列目录（含虚拟根：根目录下是各账号文件夹）
    async fn compat_list_dir(&self, path: &str) -> Result<Vec<Entry>, String> {
        let path = normalize_path(path);
        if path == "/" {
            let accounts: Vec<Account> = self.store.data.lock().unwrap().accounts.clone();
            return Ok(accounts
                .iter()
                .map(|a| Entry {
                    fid: format!("virtual:{}", a.id),
                    name: a.name.clone(),
                    is_dir: true,
                    size: 0,
                    ..Default::default()
                })
                .collect());
        }
        let (acc_id, entry) = self.resolve_path(&path).await?;
        if !entry.is_dir {
            return Err(format!("不是目录: {path}"));
        }
        let driver = self.get_driver(&acc_id).await?;
        let children = driver.list(&entry.fid).await?;
        self.index_children(&path, &acc_id, &children);
        Ok(children)
    }
}

// ---------- 端点 ----------

#[derive(Deserialize)]
#[allow(dead_code)]
pub(crate) struct CompatLoginReq {
    username: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    otp_code: String,
}

/// POST /api/auth/login —— 对齐 OpenList 登录响应
///
/// 与面板登录共用凭据校验（argon2 + 老库透明升级）与登录失败限速。
/// 限速命中按协议约定回 HTTP 200 + code 429（AList 客户端会把 message 显示出来）。
pub(crate) async fn compat_login(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(req): Json<CompatLoginReq>,
) -> Response {
    let ip = peer.ip();
    let now = Instant::now();
    if let Err(wait) = st.login_limiter.lock().unwrap().check(ip, now) {
        return compat_err(
            format!("登录失败次数过多，请 {} 秒后再试", wait.as_secs().max(1)),
            429,
        );
    }
    if !crate::auth::verify_credentials(&st, &req.username, &req.password).await {
        st.login_limiter.lock().unwrap().record_failure(ip, now);
        return compat_err("用户名或密码错误", 400);
    }
    st.login_limiter.lock().unwrap().record_success(ip);
    let token = uuid::Uuid::new_v4().to_string() + &uuid::Uuid::new_v4().simple().to_string();
    st.issue_session(token.clone());
    (
        StatusCode::OK,
        Json(json!({ "code": 200, "message": "success", "data": { "token": token } })),
    )
        .into_response()
}

#[derive(Deserialize)]
#[allow(dead_code)]
pub(crate) struct CompatListReq {
    path: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    page: i64,
    #[serde(default)]
    per_page: i64,
    #[serde(default)]
    refresh: bool,
}

/// POST /api/fs/list —— 对齐 OpenList FsListSplit
pub(crate) async fn compat_fs_list(
    State(st): State<AppState>,
    Json(req): Json<CompatListReq>,
) -> Response {
    let mut entries = match st.compat_list_dir(&req.path).await {
        Ok(e) => e,
        Err(e) => return compat_err(e, 500),
    };
    // 目录在前、按名称排序（官方由驱动决定顺序，这里保持稳定排序）
    sort_entries(&mut entries);
    let total = entries.len() as i64;
    // 对齐官方 pagination: page 从 1 起，per_page<=0 返回全部
    let per_page = if req.per_page <= 0 {
        total.max(1)
    } else {
        req.per_page
    };
    let page = if req.page <= 0 { 1 } else { req.page };
    let start = (((page - 1) * per_page).clamp(0, total)) as usize;
    let end = ((page * per_page).clamp(0, total)) as usize;
    let secret = st.store.sign_secret();
    let parent = normalize_path(&req.path);
    let content: Vec<Value> = entries[start..end]
        .iter()
        .map(|e| obj_resp_json(e, &join_path(&parent, &e.name), &secret))
        .collect();
    (
        StatusCode::OK,
        Json(json!({
            "code": 200,
            "message": "success",
            "data": {
                "content": content,
                "total": total,
                "readme": "",
                "header": "",
                "write": false,
                "provider": "",
            }
        })),
    )
        .into_response()
}

#[derive(Deserialize)]
#[allow(dead_code)]
pub(crate) struct CompatGetReq {
    path: String,
    #[serde(default)]
    password: String,
}

/// POST /api/fs/get —— 对齐 OpenList FsGet，返回含 raw_url
pub(crate) async fn compat_fs_get(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CompatGetReq>,
) -> Response {
    let path = normalize_path(&req.path);
    if path == "/" {
        return compat_err("无法获取根目录信息", 500);
    }
    let (acc_id, entry) = match st.resolve_path(&path).await {
        Ok(v) => v,
        Err(e) => return compat_err(e, 500),
    };
    let secret = st.store.sign_secret();
    if entry.is_dir {
        let mut data = obj_resp_json(&entry, &path, &secret);
        data["raw_url"] = json!("");
        data["provider"] = json!("");
        data["related"] = json!([]);
        return (
            StatusCode::OK,
            Json(json!({ "code": 200, "message": "success", "data": data })),
        )
            .into_response();
    }
    // 查询账号的 server_proxy 开关
    let server_proxy = {
        let data = st.store.data.lock().unwrap();
        data.accounts
            .iter()
            .find(|a| a.id == acc_id)
            .map(|a| a.server_proxy)
            .unwrap_or(false)
    };

    let host = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("127.0.0.1");
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("http");

    // /p 链接必须带签名（/d、/p 强制校验，见 compat_file）
    let proxy_url = format!(
        "{proto}://{host}/p{}?sign={}",
        path_encode(&path),
        sign::sign(&path, 0, &secret)
    );
    let raw_url = if server_proxy {
        // 开启服务器代理：raw_url 指向本服务 /p 路径，所有流量经本机中转
        proxy_url.clone()
    } else {
        // 关闭服务器代理：从驱动获取真实直链
        // 若驱动要求代理（如 115 直链与 UA 绑定），同样指向本服务 /p 路径
        match st.get_driver(&acc_id).await {
            Ok(driver) => match driver.download(&entry).await {
                // 驱动不需要代理 → 直接用网盘直链（该 URL 只发给已鉴权的 API 调用方）
                Ok(info) if !info.proxy => info.url,
                // 驱动要求代理，或取直链失败 → 降级为本服务代理路径
                _ => proxy_url.clone(),
            },
            Err(_) => proxy_url.clone(),
        }
    };

    let mut data = obj_resp_json(&entry, &path, &secret);
    data["raw_url"] = json!(raw_url);
    data["provider"] = json!("");
    data["related"] = json!([]);
    (
        StatusCode::OK,
        Json(json!({ "code": 200, "message": "success", "data": data })),
    )
        .into_response()
}

/// /d、/p 的查询参数（下载链接签名）
#[derive(Deserialize)]
pub(crate) struct SignQuery {
    #[serde(default)]
    sign: String,
}

/// 下载鉴权：链接签名有效 **或** 面板会话有效。
///
/// 为什么不能只看会话：播放器/TVBox 播视频时带不了 Authorization 头，官方因此把授权
/// 放进链接本身（sign 参数）。
/// 为什么附加会话这条：面板里已登录的用户直接点 /d 链接（不带 sign）不该被拦。
/// 代价是签名无状态 —— 登出/改密码不会让已发出的签名链接失效（与官方行为一致）。
fn authorize_download(
    st: &AppState,
    headers: &HeaderMap,
    path: &str,
    sign_param: &str,
) -> Result<(), sign::SignError> {
    let signed = sign::verify(path, sign_param, &st.store.sign_secret());
    if signed.is_ok() {
        return Ok(());
    }
    if let Some(token) = crate::auth::token_from_headers(headers) {
        // 会话带 TTL 与滑动续期（见 state::SESSION_TTL）
        if st.session_valid(&token) {
            return Ok(());
        }
    }
    signed
}

/// GET /d/{*path}（下载，attachment）与 /p/{*path}（代理播放，inline）
///
/// 行为由账号 `server_proxy` 开关决定：
/// - true  → 本服务中转（原有行为）
/// - false → 302 跳转真实直链，客户端直接访问网盘服务器
///
/// 鉴权：`?sign=` 链接签名（见 src/sign.rs）或有效面板会话，校验放在 `resolve_path` 之前 ——
/// 否则未登录者可用 404/400 的差异探测路径是否存在，还能借 `resolve_path`
/// "索引未命中即向上游列举"的行为消耗网盘请求。
async fn compat_file(
    State(st): State<AppState>,
    Path(raw): Path<String>,
    Query(q): Query<SignQuery>,
    headers: HeaderMap,
    disp: &'static str,
) -> Response {
    let path = normalize_path(&raw);
    if let Err(e) = authorize_download(&st, &headers, &path, &q.sign) {
        return (StatusCode::UNAUTHORIZED, e.message().to_string()).into_response();
    }
    let Ok((acc_id, entry)) = st.resolve_path(&path).await else {
        return (StatusCode::NOT_FOUND, "路径不存在").into_response();
    };
    if entry.is_dir {
        return (StatusCode::BAD_REQUEST, "是目录不是文件").into_response();
    }

    // 读取账号的 server_proxy 开关
    let server_proxy = {
        let data = st.store.data.lock().unwrap();
        data.accounts
            .iter()
            .find(|a| a.id == acc_id)
            .map(|a| a.server_proxy)
            .unwrap_or(false)
    };

    let Ok(driver) = st.get_driver(&acc_id).await else {
        return (StatusCode::BAD_REQUEST, "账号不可用").into_response();
    };

    if server_proxy {
        // 服务器代理模式：流式中转
        match proxy_stream(&driver, &entry, &headers, disp).await {
            Ok(r) => r,
            Err((s, m)) => (s, m).into_response(),
        }
    } else {
        // 直链模式：先取直链，若驱动要求代理（如 115 UA 绑定）则流式中转，否则 302 跳转
        match driver.download(&entry).await {
            Ok(info) if info.proxy => {
                // 驱动要求代理（直链与请求 UA 绑定，浏览器无法直接访问）
                match proxy_stream(&driver, &entry, &headers, disp).await {
                    Ok(r) => r,
                    Err((s, m)) => (s, m).into_response(),
                }
            }
            Ok(info) => Redirect::temporary(&info.url).into_response(),
            Err(e) => (StatusCode::BAD_GATEWAY, format!("获取直链失败: {e}")).into_response(),
        }
    }
}

pub(crate) async fn compat_down(
    State(st): State<AppState>,
    Path(raw): Path<String>,
    Query(q): Query<SignQuery>,
    headers: HeaderMap,
) -> Response {
    compat_file(State(st), Path(raw), Query(q), headers, "attachment").await
}

pub(crate) async fn compat_proxy(
    State(st): State<AppState>,
    Path(raw): Path<String>,
    Query(q): Query<SignQuery>,
    headers: HeaderMap,
) -> Response {
    compat_file(State(st), Path(raw), Query(q), headers, "inline").await
}

// ============================================================
// 写操作端点（对齐 Go 版 /api/fs/mkdir|rename|move|copy|remove|put|form）
// 全部 path-based：/账号名/目录/...，第一层为虚拟账号目录
// ============================================================

fn compat_ok(data: Value) -> Response {
    (
        StatusCode::OK,
        Json(json!({ "code": 200, "message": "success", "data": data })),
    )
        .into_response()
}

/// 对齐 Go url.PathUnescape：解码 %XX（不把 '+' 当空格）
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
            if let Ok(v) = u8::from_str_radix(hex, 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

impl AppState {
    /// 写操作定位目录：/账号名 或其子目录 -> (账号id, fid)
    pub(crate) async fn resolve_write_dir(&self, path: &str) -> Result<(String, String), String> {
        let path = normalize_path(path);
        let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if segs.is_empty() {
            return Err("路径为空".into());
        }
        let accounts: Vec<Account> = self.store.data.lock().unwrap().accounts.clone();
        let Some(acc) = accounts.iter().find(|a| a.name == segs[0]) else {
            return Err(format!("找不到网盘账号: {}", segs[0]));
        };
        // 第一层即账号目录本身：fid = 账号根目录
        if segs.len() == 1 {
            return Ok((acc.id.clone(), acc.root_fid.clone()));
        }
        let (acc_id, entry) = self.resolve_path(&path).await?;
        if !entry.is_dir {
            return Err(format!("不是目录: {path}"));
        }
        Ok((acc_id, entry.fid))
    }

    /// 写操作定位文件：返回 (账号id, 父目录fid, 目标entry)
    pub(crate) async fn resolve_write_entry(
        &self,
        path: &str,
    ) -> Result<(String, String, Entry), String> {
        let path = normalize_path(path);
        let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if segs.len() < 2 {
            return Err(format!("不支持在虚拟根目录操作: {path}"));
        }
        let (acc_id, entry) = self.resolve_path(&path).await?;
        let parent_path = match path.rfind('/') {
            Some(0) => format!("/{}", segs[0]),
            Some(i) => path[..i].to_string(),
            None => return Err(format!("路径不合法: {path}")),
        };
        let (_, parent_fid) = self.resolve_write_dir(&parent_path).await?;
        Ok((acc_id, parent_fid, entry))
    }

    /// 写操作后失效路径索引（该路径及其子树）
    fn invalidate_index_prefix(&self, path: &str) {
        let path = normalize_path(path);
        let prefix = format!("{path}/");
        self.index
            .lock()
            .unwrap()
            .retain(|k, _| k != &path && !k.starts_with(&prefix));
    }

    /// 失效某账号某目录的列表缓存（key = "{账号id}:{fid}"）
    fn invalidate_dir_cache(&self, acc_id: &str, fid: &str) {
        self.list_cache.invalidate_key(&format!("{acc_id}:{fid}"));
    }
}

#[derive(Deserialize)]
pub(crate) struct CompatMkdirReq {
    path: String,
}

/// POST /api/fs/mkdir
pub(crate) async fn compat_fs_mkdir(
    State(st): State<AppState>,
    Json(req): Json<CompatMkdirReq>,
) -> Response {
    let path = normalize_path(&req.path);
    let name = path.rsplit('/').next().unwrap_or("").to_string();
    if name.is_empty() {
        return compat_err("目录名为空", 400);
    }
    // mkdir 的目标尚不存在，解析其父目录；父目录即账号根（/账号名）时命中第 0 位
    let parent_path = match path.rfind('/') {
        Some(0) => format!("/{}", path.split('/').nth(1).unwrap_or("")),
        Some(i) => path[..i].to_string(),
        None => return compat_err(format!("路径不合法: {path}"), 400),
    };
    let (acc_id, parent_fid) = match st.resolve_write_dir(&parent_path).await {
        Ok(v) => v,
        Err(e) => return compat_err(e, 500),
    };
    let driver = match st.get_driver(&acc_id).await {
        Ok(d) => d,
        Err(e) => return compat_err(e, 500),
    };
    if let Err(e) = driver.mkdir(&parent_fid, &name).await {
        return compat_err(e, 500);
    }
    st.invalidate_dir_cache(&acc_id, &parent_fid);
    compat_ok(Value::Null)
}

#[derive(Deserialize)]
pub(crate) struct CompatRenameReq {
    path: String,
    #[serde(default)]
    name: String,
}

/// POST /api/fs/rename
pub(crate) async fn compat_fs_rename(
    State(st): State<AppState>,
    Json(req): Json<CompatRenameReq>,
) -> Response {
    if req.name.trim().is_empty() {
        return compat_err("新名称为空", 400);
    }
    let (acc_id, parent_fid, entry) = match st.resolve_write_entry(&req.path).await {
        Ok(v) => v,
        Err(e) => return compat_err(e, 500),
    };
    let driver = match st.get_driver(&acc_id).await {
        Ok(d) => d,
        Err(e) => return compat_err(e, 500),
    };
    if let Err(e) = driver.rename(&parent_fid, &entry, &req.name).await {
        return compat_err(e, 500);
    }
    let path = normalize_path(&req.path);
    st.invalidate_dir_cache(&acc_id, &parent_fid);
    st.invalidate_index_prefix(&path);
    compat_ok(Value::Null)
}

#[derive(Deserialize)]
pub(crate) struct CompatMoveCopyReq {
    #[serde(default)]
    src_dir: String,
    #[serde(default)]
    dst_dir: String,
    #[serde(default)]
    names: Vec<String>,
}

/// POST /api/fs/move
pub(crate) async fn compat_fs_move(
    State(st): State<AppState>,
    Json(req): Json<CompatMoveCopyReq>,
) -> Response {
    do_move_or_copy(&st, &req, true).await
}

/// POST /api/fs/copy
pub(crate) async fn compat_fs_copy(
    State(st): State<AppState>,
    Json(req): Json<CompatMoveCopyReq>,
) -> Response {
    do_move_or_copy(&st, &req, false).await
}

async fn do_move_or_copy(st: &AppState, req: &CompatMoveCopyReq, is_move: bool) -> Response {
    if req.names.is_empty() {
        return compat_err("names 为空", 400);
    }
    let (src_acc, src_dir_fid) = match st.resolve_write_dir(&req.src_dir).await {
        Ok(v) => v,
        Err(e) => return compat_err(e, 500),
    };
    let (dst_acc, dst_dir_fid) = match st.resolve_write_dir(&req.dst_dir).await {
        Ok(v) => v,
        Err(e) => return compat_err(e, 500),
    };
    if is_move && src_acc != dst_acc {
        return compat_err("不支持跨账号移动", 400);
    }
    let driver = match st.get_driver(&src_acc).await {
        Ok(d) => d,
        Err(e) => return compat_err(e, 500),
    };
    let src_dir = normalize_path(&req.src_dir);
    for name in &req.names {
        let path = format!("{}/{}", src_dir.trim_end_matches('/'), name);
        // (acc_id, parent_fid=src_dir_fid, entry)：带 extra 的完整 Entry
        let (_, parent_fid, entry) = match st.resolve_write_entry(&path).await {
            Ok(v) => v,
            Err(e) => return compat_err(e, 500),
        };
        let r = if is_move {
            driver.move_entry(&parent_fid, &entry, &dst_dir_fid).await
        } else {
            driver.copy(&parent_fid, &entry, &dst_dir_fid).await
        };
        if let Err(e) = r {
            return compat_err(format!("{name}: {e}"), 500);
        }
        if is_move {
            st.invalidate_index_prefix(&path);
        }
    }
    st.invalidate_dir_cache(&src_acc, &src_dir_fid);
    st.invalidate_dir_cache(&dst_acc, &dst_dir_fid);
    compat_ok(Value::Null)
}

#[derive(Deserialize)]
pub(crate) struct CompatRemoveReq {
    #[serde(default)]
    dir: String,
    #[serde(default)]
    names: Vec<String>,
}

/// POST /api/fs/remove
pub(crate) async fn compat_fs_remove(
    State(st): State<AppState>,
    Json(req): Json<CompatRemoveReq>,
) -> Response {
    if req.names.is_empty() {
        return compat_err("names 为空", 400);
    }
    let dir = normalize_path(&req.dir);
    let (acc_id, dir_fid) = match st.resolve_write_dir(&dir).await {
        Ok(v) => v,
        Err(e) => return compat_err(e, 500),
    };
    let driver = match st.get_driver(&acc_id).await {
        Ok(d) => d,
        Err(e) => return compat_err(e, 500),
    };
    for name in &req.names {
        let path = format!("{}/{}", dir.trim_end_matches('/'), name);
        let (_, parent_fid, entry) = match st.resolve_write_entry(&path).await {
            Ok(v) => v,
            Err(e) => return compat_err(e, 500),
        };
        if let Err(e) = driver.remove(&parent_fid, &entry).await {
            return compat_err(format!("{name}: {e}"), 500);
        }
        st.invalidate_index_prefix(&path);
    }
    st.invalidate_dir_cache(&acc_id, &dir_fid);
    compat_ok(Value::Null)
}

/// 上传公共流程：解析目标目录 -> 包进度 reader -> 驱动 put -> 清理进度表 + 失效缓存
async fn do_put(
    st: &AppState,
    path: &str,
    name: String,
    size: u64,
    reader: Pin<Box<dyn tokio::io::AsyncRead + Send>>,
    overwrite: bool,
) -> Result<(), String> {
    let path = normalize_path(path);
    if name.is_empty() {
        return Err("文件名为空".into());
    }
    // overwrite=false 时拒绝覆盖已存在文件（对齐 Go 版 Overwrite 头语义）
    if !overwrite && st.resolve_path(&path).await.is_ok() {
        return Err("file exists".into());
    }
    let parent_path = match path.rfind('/') {
        Some(i) if i > 0 => path[..i].to_string(),
        _ => return Err(format!("不支持在虚拟根目录上传: {path}")),
    };
    let (acc_id, dst_fid) = st.resolve_write_dir(&parent_path).await?;
    let driver = st.get_driver(&acc_id).await?;

    let progress = Arc::new(AtomicU64::new(0));
    st.upload_progress
        .lock()
        .unwrap()
        .insert(path.clone(), progress.clone());
    let input = PutInput {
        name,
        size,
        reader: Box::pin(super::drivers::ProgressReader::new(reader, progress)),
    };
    let r = driver.put(&dst_fid, input).await;
    st.upload_progress.lock().unwrap().remove(&path);
    r?;
    st.invalidate_dir_cache(&acc_id, &dst_fid);
    Ok(())
}

/// POST /api/fs/put —— 原始 body 流式上传
/// 头：File-Path（URL 转义全路径）、Overwrite（缺省 true）、X-File-Size（Content-Length 缺省时）
pub(crate) async fn compat_fs_put(
    State(st): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Body,
) -> Response {
    let Some(raw) = headers.get("File-Path").and_then(|v| v.to_str().ok()) else {
        return compat_err("缺少 File-Path 头", 400);
    };
    let path = percent_decode(raw);
    let overwrite = headers
        .get("Overwrite")
        .and_then(|v| v.to_str().ok())
        .map(|v| v != "false")
        .unwrap_or(true);
    // size：Content-Length 优先，其次 X-File-Size（对齐 Go 版 FsStream）
    let size = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&s| s > 0)
        .or_else(|| {
            headers
                .get("X-File-Size")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
        })
        .unwrap_or(0);
    let name = normalize_path(&path)
        .rsplit('/')
        .next()
        .unwrap_or("")
        .to_string();

    let reader = StreamReader::new(body.into_data_stream().map_err(io_err));
    match do_put(&st, &path, name, size, Box::pin(reader), overwrite).await {
        Ok(()) => compat_ok(Value::Null),
        Err(e) => compat_err(e, 500),
    }
}

/// POST /api/fs/form —— multipart 表单上传（浏览器用）
/// 头：File-Path（URL 转义全路径）、X-File-Size（推荐）；表单字段：file
pub(crate) async fn compat_fs_form(
    State(st): State<AppState>,
    headers: HeaderMap,
    mut multipart: axum::extract::Multipart,
) -> Response {
    let Some(raw) = headers.get("File-Path").and_then(|v| v.to_str().ok()) else {
        return compat_err("缺少 File-Path 头", 400);
    };
    let path = percent_decode(raw);
    let overwrite = headers
        .get("Overwrite")
        .and_then(|v| v.to_str().ok())
        .map(|v| v != "false")
        .unwrap_or(true);
    let header_size = headers
        .get("X-File-Size")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());

    // 找到 file 字段并落盘（对齐 Go 版 c.FormFile("file")）
    // Field 借用自 multipart（非 'static），且借用不能跨 next_field 迭代（E0499），
    // 所以在同一个迭代内直接把命中的 field 落到临时文件，借用随迭代结束
    use tokio::io::AsyncWriteExt;
    let tmp_path = std::env::temp_dir().join(format!("openlist-rs-form-{}", uuid::Uuid::new_v4()));
    let mut spooled = false;
    let mut fallback_name = String::new();
    let mut spool_err: Option<String> = None;
    loop {
        let Ok(Some(field)) = multipart.next_field().await else {
            break;
        };
        if field.name() != Some("file") {
            continue;
        }
        fallback_name = field.file_name().unwrap_or("").to_string();
        let spool = async {
            let mut f = tokio::fs::File::create(&tmp_path)
                .await
                .map_err(|e| format!("创建临时文件失败: {e}"))?;
            let mut field = field;
            while let Some(chunk) = field
                .chunk()
                .await
                .map_err(|e| format!("读取上传内容失败: {e}"))?
            {
                f.write_all(&chunk)
                    .await
                    .map_err(|e| format!("写临时文件失败: {e}"))?;
            }
            f.flush()
                .await
                .map_err(|e| format!("刷新临时文件失败: {e}"))?;
            Ok::<(), String>(())
        };
        match spool.await {
            Ok(()) => spooled = true,
            Err(e) => spool_err = Some(e),
        }
        break;
    }
    if let Some(e) = spool_err {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        return compat_err(e, 500);
    }
    if !spooled {
        return compat_err("缺少 file 表单字段", 400);
    }
    // 名称优先取 File-Path 末段（对齐 Go 版 dir, name := stdpath.Split(path)）
    let name = normalize_path(&path)
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            if fallback_name.is_empty() {
                None
            } else {
                Some(fallback_name.clone())
            }
        })
        .unwrap_or_default();

    let size = match header_size {
        Some(s) if s > 0 => s,
        _ => tokio::fs::metadata(&tmp_path)
            .await
            .map(|m| m.len())
            .unwrap_or(0),
    };
    let file = match tokio::fs::File::open(&tmp_path).await {
        Ok(f) => f,
        Err(e) => {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return compat_err(format!("打开临时文件失败: {e}"), 500);
        }
    };
    // 交付给驱动；ProgressReader 正确传递 Pending 后，tokio::fs::File 也能完整读出（回归见 drivers/mod.rs 测试）
    let r = do_put(&st, &path, name, size, Box::pin(file), overwrite).await;
    let _ = tokio::fs::remove_file(&tmp_path).await;
    match r {
        Ok(()) => compat_ok(Value::Null),
        Err(e) => compat_err(e, 500),
    }
}

/// GET /api/fs/put/progress —— 活跃上传进度 { "<路径>": 已上传字节 }
pub(crate) async fn compat_fs_put_progress(State(st): State<AppState>) -> Response {
    let map = st.upload_progress.lock().unwrap();
    let mut data = serde_json::Map::new();
    for (k, v) in map.iter() {
        data.insert(k.clone(), json!(v.load(Ordering::Relaxed)));
    }
    compat_ok(Value::Object(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_path() {
        assert_eq!(normalize_path("/a/b"), "/a/b");
        assert_eq!(normalize_path("a/b"), "/a/b");
        assert_eq!(normalize_path("/a/b/"), "/a/b"); // 去尾斜杠
        assert_eq!(normalize_path("/"), "/");
        assert_eq!(normalize_path(""), "/");
        assert_eq!(normalize_path("  /a/  "), "/a"); // 去首尾空白
    }

    #[test]
    fn test_path_encode() {
        // 保留 '/'，空格与中文按 UTF-8 百分号编码
        assert_eq!(path_encode("/a b/c"), "/a%20b/c");
        assert_eq!(path_encode("/中文"), "/%E4%B8%AD%E6%96%87");
        // unreserved + Go 版放行的子分隔符
        assert_eq!(path_encode("/a-b_c.d~e"), "/a-b_c.d~e");
        assert_eq!(path_encode("/a@b!c(d)e'f*g"), "/a@b!c(d)e'f*g");
        assert_eq!(path_encode("/"), "/");
    }

    #[test]
    fn test_obj_type() {
        assert_eq!(obj_type("folder", true), T_FOLDER); // 目录优先，不看扩展名
        assert_eq!(obj_type("a.MP4", false), T_VIDEO); // 扩展名大小写不敏感
        assert_eq!(obj_type("a.mkv", false), T_VIDEO);
        assert_eq!(obj_type("a.mp3", false), T_AUDIO);
        assert_eq!(obj_type("a.png", false), T_IMAGE);
        assert_eq!(obj_type("a.md", false), T_TEXT);
        assert_eq!(obj_type("a.bin", false), T_UNKNOWN);
        assert_eq!(obj_type("noext", false), T_UNKNOWN);
    }
}
