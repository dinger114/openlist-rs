//! WebDAV 服务（`/dav`）
//!
//! 把已挂载的各存储按 WebDAV 协议暴露给访达 / Windows 资源管理器 / rclone / davfs2 等客户端。
//!
//! 设计要点：
//! - **自带鉴权**：`auth_guard` 只拦 `/api` 前缀，所以这里自己校验 —— Basic（面板账号密码）
//!   或 Bearer（面板会话 token），失败按 TCP 对端 IP 走 `login_limiter` 限速；OPTIONS 免鉴权。
//! - **路径复用兼容层**：虚拟根 = 各账号文件夹（`/dav/<账号名>/...`），与 `/api/fs/list` 同一套
//!   语义，解析走 `AppState::resolve_path` / `list_dir_cached`。
//! - **读写映射驱动方法**：`list/download/put/mkdir/rename/move_entry/copy/remove`，不重写流。
//! - **XML 手写**：multistatus 自己拼（配 `xml_escape`），不引 XML crate。
//! - **LOCK 不强制**：只发/回收 token（访达与资源管理器写操作前会 LOCK），`If:` 头校验留后续。

use axum::{
    body::Body,
    extract::{ConnectInfo, Path, State},
    http::{header, HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use base64::Engine;
use futures_util::TryStreamExt;
use std::net::SocketAddr;
use std::pin::Pin;
use tokio::io::AsyncRead;

use crate::config::Entry;
use crate::drivers::PutInput;
use crate::state::AppState;

/// OPTIONS 广告支持的方法
const DAV_ALLOW: &str =
    "OPTIONS, GET, HEAD, PUT, POST, DELETE, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK";

/// `any("/dav")` —— 虚拟根（无 path 参数）
pub(crate) async fn handle_root(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    uri: Uri,
    body: Body,
) -> Response {
    dispatch(st, peer, method, headers, uri, "/".to_string(), body).await
}

/// `any("/dav/{*path}")`
pub(crate) async fn handle_path(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(path): Path<String>,
    method: Method,
    headers: HeaderMap,
    uri: Uri,
    body: Body,
) -> Response {
    dispatch(st, peer, method, headers, uri, path, body).await
}

async fn dispatch(
    st: AppState,
    peer: SocketAddr,
    method: Method,
    headers: HeaderMap,
    _uri: Uri,
    raw_path: String,
    body: Body,
) -> Response {
    let mut resp = match method {
        // 客户端探测能力时不带凭据，必须放行
        Method::OPTIONS => options_response(),
        _ => {
            if let Err(r) = authorize(&st, peer.ip(), &headers).await {
                return *r;
            }
            match method.as_str() {
                "PROPFIND" => {
                    let depth = parse_depth(headers.get("depth").and_then(|v| v.to_str().ok()));
                    propfind(&st, &raw_path, depth, &headers).await
                }
                "GET" => get_file(&st, &raw_path, &headers, false).await,
                "HEAD" => get_file(&st, &raw_path, &headers, true).await,
                "PUT" => put_file(&st, &raw_path, &headers, body).await,
                "MKCOL" => mkcol(&st, &raw_path).await,
                "DELETE" => delete_entry(&st, &raw_path).await,
                "MOVE" => move_or_copy(&st, &raw_path, &headers, true).await,
                "COPY" => move_or_copy(&st, &raw_path, &headers, false).await,
                "LOCK" => lock_resource(&raw_path, &headers, body).await,
                "UNLOCK" => unlock_resource(&raw_path, &headers).await,
                "PROPPATCH" => proppatch(&raw_path).await,
                _ => (
                    StatusCode::METHOD_NOT_ALLOWED,
                    [(header::ALLOW, DAV_ALLOW)],
                    format!("不支持的方法: {method}"),
                )
                    .into_response(),
            }
        }
    };
    resp.headers_mut().insert(
        header::HeaderName::from_static("dav"),
        header::HeaderValue::from_static("1, 2"),
    );
    resp.headers_mut().insert(
        header::HeaderName::from_static("ms-author-via"),
        header::HeaderValue::from_static("DAV"),
    );
    resp
}

/// OPTIONS：回能力头（DAV 版本、允许的方法、支持 Range）
fn options_response() -> Response {
    (
        StatusCode::OK,
        [
            (header::ALLOW, DAV_ALLOW),
            (header::HeaderName::from_static("accept-ranges"), "bytes"),
        ],
        "",
    )
        .into_response()
}

// ---------- 鉴权 ----------

/// 解析 `Authorization: Basic base64(user:pass)`
fn basic_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let b64 = raw
        .strip_prefix("Basic ")
        .or_else(|| raw.strip_prefix("basic "))?
        .trim();
    let decoded = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (user, pass) = text.split_once(':')?;
    Some((user.to_string(), pass.to_string()))
}

/// Basic（面板账号）或 Bearer（面板会话 token）鉴权；失败返回已构造好的响应
async fn authorize(
    st: &AppState,
    ip: std::net::IpAddr,
    headers: &HeaderMap,
) -> Result<(), Box<Response>> {
    let now = std::time::Instant::now();
    if let Err(wait) = st.login_limiter.lock().unwrap().check(ip, now) {
        return Err(Box::new(
            (
                StatusCode::TOO_MANY_REQUESTS,
                format!("认证失败次数过多，请 {} 秒后再试", wait.as_secs()),
            )
                .into_response(),
        ));
    }

    // Bearer：面板会话 token（与 /d、/p 的会话鉴权同一套）
    if let Some(token) = crate::auth::token_from_headers(headers) {
        if st.session_valid(&token) {
            return Ok(());
        }
    }

    let Some((user, pass)) = basic_credentials(headers) else {
        return Err(Box::new(unauthorized()));
    };
    if crate::auth::verify_credentials(st, &user, &pass).await {
        st.login_limiter.lock().unwrap().record_success(ip);
        Ok(())
    } else {
        st.login_limiter.lock().unwrap().record_failure(ip, now);
        Err(Box::new(unauthorized()))
    }
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Basic realm=\"openlist\"")],
        "未认证",
    )
        .into_response()
}

// ---------- 路径与 XML 纯函数 ----------

/// 单次 PROPFIND 最多返回的条目数（大目录防爆；超出截断并在响应头标注）
const MAX_PROPFIND_ITEMS: usize = 20_000;

/// 逐段 percent-encode（保留 `/` 作为分隔符）。
///
/// 只放行 unreserved 与少数安全 sub-delims；`&`、`'`、空格、中文一律编码 ——
/// href 要同时过 XML 与客户端解析，原样输出会踩两个坑。
fn href_encode(path: &str) -> String {
    let mut out = String::new();
    for (i, seg) in path.split('/').enumerate() {
        if i > 0 {
            out.push('/');
        }
        for b in seg.as_bytes() {
            match *b {
                b'A'..=b'Z'
                | b'a'..=b'z'
                | b'0'..=b'9'
                | b'-'
                | b'.'
                | b'_'
                | b'~'
                | b'!'
                | b'$'
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'@' => out.push(*b as char),
                _ => out.push_str(&format!("%{b:02X}")),
            }
        }
    }
    out
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// 毫秒时间戳 → RFC 1123（GMT），HTTP 日期头与 `getlastmodified` 用
fn http_date(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (y, m, d) = crate::drivers::timeutil::civil_from_days(days);
    let wd = crate::drivers::timeutil::weekday_short_utc(days);
    format!(
        "{wd}, {:02} {} {y:04} {:02}:{:02}:{:02} GMT",
        d,
        MONTHS[(m as usize).clamp(1, 12) - 1],
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60
    )
}

/// 毫秒时间戳 → ISO 8601（`creationdate` 用）
fn iso8601(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (y, m, d) = crate::drivers::timeutil::civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60
    )
}

/// `Depth` 头 → 深度。缺省与 `infinity` 都按 1 处理：一次 PROPFIND 拉全站会打爆大盘
fn parse_depth(h: Option<&str>) -> u32 {
    match h.map(str::trim) {
        Some("0") => 0,
        _ => 1,
    }
}

/// 资源的 etag：驱动给了就用，否则按大小 + 修改时间合成
fn etag_of(e: &Entry) -> String {
    match &e.etag {
        Some(t) if !t.is_empty() => {
            if t.starts_with('"') {
                t.clone()
            } else {
                format!("\"{t}\"")
            }
        }
        _ => format!("\"{}-{}\"", e.size, e.updated_at.unwrap_or(0)),
    }
}

/// DAV href：`/dav` + 编码后的路径（目录带尾斜杠，客户端据此判定集合）
fn href_for(path: &str, is_dir: bool) -> String {
    let enc = href_encode(path);
    let mut href = format!("/dav{enc}");
    if is_dir && !href.ends_with('/') {
        href.push('/');
    }
    href
}

/// 单条 `<D:response>`
fn propfind_response(href: &str, e: &Entry) -> String {
    let mut props = format!("<D:displayname>{}</D:displayname>", xml_escape(&e.name));
    if e.is_dir {
        props.push_str("<D:resourcetype><D:collection/></D:resourcetype>");
    } else {
        props.push_str("<D:resourcetype/>");
        props.push_str(&format!(
            "<D:getcontentlength>{}</D:getcontentlength>",
            e.size
        ));
        props.push_str(&format!(
            "<D:getcontenttype>{}</D:getcontenttype>",
            xml_escape(crate::api::content_type_by_ext(&e.name))
        ));
    }
    if let Some(ms) = e.updated_at {
        props.push_str(&format!(
            "<D:getlastmodified>{}</D:getlastmodified>",
            http_date(ms)
        ));
        props.push_str(&format!("<D:creationdate>{}</D:creationdate>", iso8601(ms)));
    }
    props.push_str(&format!(
        "<D:getetag>{}</D:getetag>",
        xml_escape(&etag_of(e))
    ));
    format!(
        "<D:response><D:href>{}</D:href><D:propstat><D:prop>{props}</D:prop>\
         <D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>",
        xml_escape(href)
    )
}

/// 拼完整 multistatus 文档
fn multistatus(responses: &[String]) -> String {
    let mut s = String::with_capacity(256 + responses.len() * 400);
    s.push_str("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<D:multistatus xmlns:D=\"DAV:\">");
    for r in responses {
        s.push_str(r);
    }
    s.push_str("</D:multistatus>");
    s
}

fn multistatus_response(items: &[(String, Entry)], truncated: bool) -> Response {
    let responses: Vec<String> = items
        .iter()
        .map(|(href, e)| propfind_response(href, e))
        .collect();
    let body = multistatus(&responses);
    let mut resp = (
        StatusCode::MULTI_STATUS,
        [(
            header::CONTENT_TYPE,
            "application/xml; charset=utf-8".to_string(),
        )],
        body,
    )
        .into_response();
    if truncated {
        resp.headers_mut().insert(
            header::HeaderName::from_static("x-dav-truncated"),
            header::HeaderValue::from_static("1"),
        );
    }
    resp
}

// ---------- PROPFIND ----------

async fn propfind(st: &AppState, raw_path: &str, depth: u32, headers: &HeaderMap) -> Response {
    let path = crate::compat::normalize_path(raw_path);
    // 客户端要的是 infinity 却被封顶到 1，得让它知道结果不完整
    let asked_infinity = headers
        .get("depth")
        .and_then(|v| v.to_str().ok())
        .map(|d| d.eq_ignore_ascii_case("infinity"))
        .unwrap_or(false);

    // 虚拟根：子项是各账号文件夹（与 /api/fs/list 的根目录一致）
    if path == "/" {
        let root = (
            href_for("/", true),
            Entry {
                name: "OpenList".to_string(),
                is_dir: true,
                ..Default::default()
            },
        );
        if depth == 0 {
            return multistatus_response(&[root], false);
        }
        let accounts = st.store.data.lock().unwrap().accounts.clone();
        let mut items: Vec<(String, Entry)> = vec![root];
        for a in accounts.iter().filter(|a| a.enabled) {
            items.push((
                href_for(&format!("/{}", a.name), true),
                Entry {
                    fid: a.root_fid.clone(),
                    name: a.name.clone(),
                    is_dir: true,
                    ..Default::default()
                },
            ));
        }
        return multistatus_response(&items, asked_infinity);
    }

    let (acc_id, entry) = match st.resolve_path(&path).await {
        Ok(v) => v,
        Err(e) => return map_driver_error(&e),
    };

    let mut items: Vec<(String, Entry)> = vec![(href_for(&path, entry.is_dir), entry.clone())];
    let mut truncated = asked_infinity;
    if depth >= 1 && entry.is_dir {
        match st.list_dir_cached(&acc_id, &entry.fid, false).await {
            Ok(children) => {
                for c in children.iter() {
                    if items.len() >= MAX_PROPFIND_ITEMS {
                        truncated = true;
                        break;
                    }
                    let child_path = format!("{}/{}", path.trim_end_matches('/'), c.name);
                    items.push((href_for(&child_path, c.is_dir), c.clone()));
                }
            }
            Err(e) => return map_driver_error(&e),
        }
    }
    multistatus_response(&items, truncated)
}

/// 驱动错误 → DAV 状态码（驱动侧暂无错误枚举，按关键字粗分；有枚举后替换）
fn map_driver_error(msg: &str) -> Response {
    let code = if msg.contains("不存在") || msg.contains("not found") {
        StatusCode::NOT_FOUND
    } else if msg.contains("只读") || msg.contains("不支持") || msg.contains("未实现") {
        StatusCode::FORBIDDEN
    } else if msg.contains("cookie") || msg.contains("token") || msg.contains("未登录") {
        StatusCode::UNAUTHORIZED
    } else {
        StatusCode::BAD_GATEWAY
    };
    (code, msg.to_string()).into_response()
}

// ---------- GET / HEAD ----------

/// HEAD：只回元信息，不去取直链（省一次上游往返；DAV 客户端靠它判断大小/时间）
fn head_response(e: &Entry) -> Response {
    let mut resp = (StatusCode::OK, Body::empty()).into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_str(crate::api::content_type_by_ext(&e.name))
            .unwrap_or_else(|_| header::HeaderValue::from_static("application/octet-stream")),
    );
    h.insert(
        header::CONTENT_LENGTH,
        header::HeaderValue::from_str(&e.size.to_string())
            .unwrap_or_else(|_| header::HeaderValue::from_static("0")),
    );
    h.insert(
        header::ACCEPT_RANGES,
        header::HeaderValue::from_static("bytes"),
    );
    if let Ok(v) = header::HeaderValue::from_str(&etag_of(e)) {
        h.insert(header::ETAG, v);
    }
    if let Some(ms) = e.updated_at {
        if let Ok(v) = header::HeaderValue::from_str(&http_date(ms)) {
            h.insert(header::LAST_MODIFIED, v);
        }
    }
    resp
}

/// GET/HEAD：沿用兼容层的取流策略 —— 账号开 `server_proxy` 或驱动要求代理时服务端中转
/// （Range 由 `proxy_stream` 处理），否则 302 跳直链让客户端直连。
async fn get_file(st: &AppState, raw_path: &str, headers: &HeaderMap, head_only: bool) -> Response {
    let path = crate::compat::normalize_path(raw_path);
    let (acc_id, entry) = match st.resolve_path(&path).await {
        Ok(v) => v,
        Err(e) => return map_driver_error(&e),
    };
    if entry.is_dir {
        return (
            StatusCode::METHOD_NOT_ALLOWED,
            [(header::ALLOW, "OPTIONS, PROPFIND")],
            "是目录，不是文件",
        )
            .into_response();
    }
    if head_only {
        return head_response(&entry);
    }

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
        return match crate::api::proxy_stream(&driver, &entry, headers, "inline").await {
            Ok(r) => r,
            Err((s, m)) => (s, m).into_response(),
        };
    }
    match driver.download(&entry).await {
        // 直链与请求 UA 绑定时浏览器直连会 403，改走中转
        Ok(info) if info.proxy => {
            match crate::api::proxy_stream(&driver, &entry, headers, "inline").await {
                Ok(r) => r,
                Err((s, m)) => (s, m).into_response(),
            }
        }
        Ok(info) => axum::response::Redirect::temporary(&info.url).into_response(),
        Err(e) => (StatusCode::BAD_GATEWAY, format!("获取直链失败: {e}")).into_response(),
    }
}

// ---------- 写操作 ----------

/// 拆出 (父目录路径, 末段名)；虚拟根（`/` 或 `/账号名`）不可直接写
fn split_parent(path: &str) -> Option<(String, String)> {
    let name = path.rsplit('/').next().unwrap_or("").to_string();
    if name.is_empty() {
        return None;
    }
    match path.rfind('/') {
        Some(i) if i > 0 => Some((path[..i].to_string(), name)),
        _ => None,
    }
}

/// PUT：流式落盘（不缓冲整文件），Content-Length 必填
async fn put_file(st: &AppState, raw_path: &str, headers: &HeaderMap, body: Body) -> Response {
    let path = crate::compat::normalize_path(raw_path);
    let Some((parent_path, name)) = split_parent(&path) else {
        return (StatusCode::CONFLICT, "不能在虚拟根目录上传").into_response();
    };
    let Some(size) = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
    else {
        // DAV 客户端（含访达）总是带 Content-Length；缺了说明是异常请求
        return (StatusCode::LENGTH_REQUIRED, "PUT 需要 Content-Length").into_response();
    };
    let existed = st.resolve_path(&path).await.is_ok();
    let (acc_id, dst_fid) = match st.resolve_write_dir(&parent_path).await {
        Ok(v) => v,
        Err(e) => return map_driver_error(&e),
    };
    let Ok(driver) = st.get_driver(&acc_id).await else {
        return (StatusCode::BAD_REQUEST, "账号不可用").into_response();
    };

    let reader: Pin<Box<dyn AsyncRead + Send>> = Box::pin(tokio_util::io::StreamReader::new(
        body.into_data_stream().map_err(std::io::Error::other),
    ));
    let input = PutInput { name, size, reader };
    if let Err(e) = driver.put(&dst_fid, input).await {
        return map_driver_error(&e);
    }
    st.invalidate_dir_cache(&acc_id, &dst_fid);
    st.invalidate_index_prefix(&path);

    if existed {
        StatusCode::NO_CONTENT.into_response()
    } else {
        let mut resp = StatusCode::CREATED.into_response();
        if let Ok(v) = header::HeaderValue::from_str(&href_for(&path, false)) {
            resp.headers_mut().insert(header::LOCATION, v);
        }
        resp
    }
}

/// MKCOL：新建集合。已存在按 RFC 4918 回 405；请求体忽略（部分客户端会发 XML）
async fn mkcol(st: &AppState, raw_path: &str) -> Response {
    let path = crate::compat::normalize_path(raw_path);
    let Some((parent_path, name)) = split_parent(&path) else {
        return (StatusCode::CONFLICT, "不能在虚拟根目录新建集合").into_response();
    };
    if st.resolve_path(&path).await.is_ok() {
        return (StatusCode::METHOD_NOT_ALLOWED, "已存在").into_response();
    }
    let (acc_id, parent_fid) = match st.resolve_write_dir(&parent_path).await {
        Ok(v) => v,
        Err(e) => return map_driver_error(&e),
    };
    let Ok(driver) = st.get_driver(&acc_id).await else {
        return (StatusCode::BAD_REQUEST, "账号不可用").into_response();
    };
    if let Err(e) = driver.mkdir(&parent_fid, &name).await {
        return map_driver_error(&e);
    }
    st.invalidate_dir_cache(&acc_id, &parent_fid);
    st.invalidate_index_prefix(&path);
    StatusCode::CREATED.into_response()
}

/// DELETE：文件或目录（驱动侧决定递归语义，如 local 用 remove_dir_all）
async fn delete_entry(st: &AppState, raw_path: &str) -> Response {
    let path = crate::compat::normalize_path(raw_path);
    let (acc_id, parent_fid, entry) = match st.resolve_write_entry(&path).await {
        Ok(v) => v,
        Err(e) => return map_driver_error(&e),
    };
    let Ok(driver) = st.get_driver(&acc_id).await else {
        return (StatusCode::BAD_REQUEST, "账号不可用").into_response();
    };
    if let Err(e) = driver.remove(&parent_fid, &entry).await {
        return map_driver_error(&e);
    }
    st.invalidate_dir_cache(&acc_id, &parent_fid);
    st.invalidate_index_prefix(&path);
    StatusCode::NO_CONTENT.into_response()
}

/// 解析 `Destination` 头（绝对 URL 或绝对路径），返回本服务内的路径
fn dav_destination(raw: &str, host_header: Option<&str>) -> Option<String> {
    let raw = raw.trim();
    let path = if let Some(rest) = raw
        .strip_prefix("http://")
        .or_else(|| raw.strip_prefix("https://"))
    {
        // 带主机：主机不同则拒绝（跨服务复制无意义）
        let i = rest.find('/')?;
        let (host, p) = (&rest[..i], &rest[i..]);
        if let Some(h) = host_header {
            if !host.eq_ignore_ascii_case(h) {
                return None;
            }
        }
        p
    } else {
        raw
    };
    let p = path.split('?').next().unwrap_or(path);
    let p = p.strip_prefix("/dav").unwrap_or(p);
    let p = if p.is_empty() { "/" } else { p };
    Some(crate::compat::normalize_path(
        &crate::compat::percent_decode(p),
    ))
}

/// MOVE / COPY：同账号内改名或跨目录搬运
async fn move_or_copy(
    st: &AppState,
    raw_path: &str,
    headers: &HeaderMap,
    is_move: bool,
) -> Response {
    let src = crate::compat::normalize_path(raw_path);
    let Some(dest_raw) = headers.get("destination").and_then(|v| v.to_str().ok()) else {
        return (StatusCode::BAD_REQUEST, "缺少 Destination 头").into_response();
    };
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok());
    let Some(dest) = dav_destination(dest_raw, host) else {
        return (StatusCode::BAD_REQUEST, "Destination 不在本服务").into_response();
    };
    if dest == src {
        return (StatusCode::FORBIDDEN, "源与目标相同").into_response();
    }
    if dest.starts_with(&format!("{}/", src.trim_end_matches('/'))) {
        return (StatusCode::FORBIDDEN, "不能把集合搬进自身子目录").into_response();
    }
    let overwrite = !headers
        .get("overwrite")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("F"))
        .unwrap_or(false);
    let dest_exists = st.resolve_path(&dest).await.is_ok();
    if dest_exists && !overwrite {
        return (StatusCode::PRECONDITION_FAILED, "目标已存在且 Overwrite: F").into_response();
    }

    let (acc_id, src_parent_fid, entry) = match st.resolve_write_entry(&src).await {
        Ok(v) => v,
        Err(e) => return map_driver_error(&e),
    };
    let Some((dest_parent_path, dest_name)) = split_parent(&dest) else {
        return (StatusCode::CONFLICT, "目标路径不合法").into_response();
    };
    let (dst_acc, dst_parent_fid) = match st.resolve_write_dir(&dest_parent_path).await {
        Ok(v) => v,
        Err(e) => return map_driver_error(&e),
    };
    if dst_acc != acc_id {
        return (StatusCode::BAD_GATEWAY, "不支持跨账号搬运").into_response();
    }
    let Ok(driver) = st.get_driver(&acc_id).await else {
        return (StatusCode::BAD_REQUEST, "账号不可用").into_response();
    };

    // 同目录改名直接 rename；否则搬进目标目录（驱动 copy/move 只认目录 fid，保留原名）
    let r = if src_parent_fid == dst_parent_fid {
        driver.rename(&src_parent_fid, &entry, &dest_name).await
    } else {
        let r = if is_move {
            driver
                .move_entry(&src_parent_fid, &entry, &dst_parent_fid)
                .await
        } else {
            driver.copy(&src_parent_fid, &entry, &dst_parent_fid).await
        };
        match r {
            // 目标名与原名不同：驱动只认目录 fid（落地保留原名），再改名到客户端要的名字。
            // 改名对象是「目标目录 + 原名」——先失效目标目录缓存，否则索引还看不到刚落地的文件
            Ok(()) if dest_name != entry.name => {
                st.invalidate_dir_cache(&acc_id, &dst_parent_fid);
                st.invalidate_index_prefix(&dest_parent_path);
                let landed = format!("{}/{}", dest_parent_path.trim_end_matches('/'), entry.name);
                match st.resolve_write_entry(&landed).await {
                    Ok((_, parent, moved)) => driver.rename(&parent, &moved, &dest_name).await,
                    Err(e) => Err(e),
                }
            }
            other => other,
        }
    };
    if let Err(e) = r {
        return map_driver_error(&e);
    }
    st.invalidate_dir_cache(&acc_id, &src_parent_fid);
    st.invalidate_dir_cache(&acc_id, &dst_parent_fid);
    st.invalidate_index_prefix(&src);
    st.invalidate_index_prefix(&dest);

    if dest_exists {
        StatusCode::NO_CONTENT.into_response()
    } else {
        StatusCode::CREATED.into_response()
    }
}

// ---------- 锁 ----------

struct LockEntry {
    path: String,
    expires: std::time::Instant,
}

/// 进程内锁表（单管理员场景够用；重启即失效，客户端会重新 LOCK）
fn locks() -> &'static std::sync::Mutex<std::collections::HashMap<String, LockEntry>> {
    static LOCKS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, LockEntry>>,
    > = std::sync::OnceLock::new();
    LOCKS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// `Timeout: Second-3600` / `Infinite` → 秒数（默认 1 小时，封顶 7 天）
fn parse_timeout(headers: &HeaderMap) -> u64 {
    let raw = headers
        .get("timeout")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    for part in raw.split(',') {
        let p = part.trim();
        if let Some(n) = p.strip_prefix("Second-") {
            if let Ok(v) = n.parse::<u64>() {
                return v.clamp(60, 7 * 24 * 3600);
            }
        }
    }
    3600
}

fn sweep_locks(map: &mut std::collections::HashMap<String, LockEntry>) {
    let now = std::time::Instant::now();
    map.retain(|_, l| l.expires > now);
}

fn activelock_xml(token: &str, depth: u32, secs: u64) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<D:prop xmlns:D=\"DAV:\"><D:lockdiscovery>\
         <D:activelock><D:locktype><D:write/></D:locktype>\
         <D:lockscope><D:exclusive/></D:lockscope><D:depth>{depth}</D:depth>\
         <D:timeout>Second-{secs}</D:timeout>\
         <D:locktoken><D:href>{token}</D:href></D:locktoken></D:activelock>\
         </D:lockdiscovery></D:prop>"
    )
}

/// LOCK：发新锁（空 body = 刷新）。不做 `If:` 强制校验，只保证客户端拿到 token
async fn lock_resource(raw_path: &str, headers: &HeaderMap, body: Body) -> Response {
    let path = crate::compat::normalize_path(raw_path);
    let depth = parse_depth(headers.get("depth").and_then(|v| v.to_str().ok()));
    let secs = parse_timeout(headers);
    let has_body = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .map(|n| n > 0)
        .unwrap_or(false);
    let _ = body; // lockinfo 内容不参与决策（独占写锁）

    if !has_body {
        // 刷新：从 If / Lock-Token 里找已发出的 token
        let mut map = locks().lock().unwrap();
        sweep_locks(&mut map);
        let if_hdr = headers
            .get("if")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let token = map
            .iter()
            .find(|(t, _)| if_hdr.contains(t.as_str()))
            .map(|(t, _)| t.clone());
        match token {
            Some(t) => {
                if let Some(l) = map.get_mut(&t) {
                    l.expires = std::time::Instant::now() + std::time::Duration::from_secs(secs);
                }
                let mut resp = (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "application/xml; charset=utf-8")],
                    activelock_xml(&t, depth, secs),
                )
                    .into_response();
                if let Ok(v) = header::HeaderValue::from_str(&format!("<{t}>")) {
                    resp.headers_mut().insert("lock-token", v);
                }
                resp
            }
            None => (StatusCode::BAD_REQUEST, "刷新锁需要 If 头带锁 token").into_response(),
        }
    } else {
        let token = format!("opaquelocktoken:{}", uuid::Uuid::new_v4());
        {
            let mut map = locks().lock().unwrap();
            sweep_locks(&mut map);
            // 同一路径重复 LOCK：丢掉旧锁让新 token 生效（不强制 If 校验，避免客户端忘了 UNLOCK 就写不动）
            map.retain(|_, l| l.path != path);
            map.insert(
                token.clone(),
                LockEntry {
                    path: path.clone(),
                    expires: std::time::Instant::now() + std::time::Duration::from_secs(secs),
                },
            );
        }
        let mut resp = (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/xml; charset=utf-8")],
            activelock_xml(&token, depth, secs),
        )
            .into_response();
        if let Ok(v) = header::HeaderValue::from_str(&format!("<{token}>")) {
            resp.headers_mut().insert("lock-token", v);
        }
        resp
    }
}

/// UNLOCK：回收 token
async fn unlock_resource(_raw_path: &str, headers: &HeaderMap) -> Response {
    let raw = headers
        .get("lock-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .to_string();
    if raw.is_empty() {
        return (StatusCode::BAD_REQUEST, "缺少 Lock-Token 头").into_response();
    }
    let mut map = locks().lock().unwrap();
    sweep_locks(&mut map);
    if map.remove(&raw).is_some() {
        StatusCode::NO_CONTENT.into_response()
    } else {
        (StatusCode::CONFLICT, "锁 token 不存在").into_response()
    }
}

/// PROPPATCH：属性一律只读（回 403 propstat），不做属性持久化
async fn proppatch(_raw_path: &str) -> Response {
    let body = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<D:multistatus xmlns:D=\"DAV:\">\
                <D:response><D:propstat><D:prop/><D:status>HTTP/1.1 403 Forbidden</D:status>\
                </D:propstat></D:response></D:multistatus>";
    (
        StatusCode::MULTI_STATUS,
        [(header::CONTENT_TYPE, "application/xml; charset=utf-8")],
        body,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_credentials_parses_header() {
        let v = base64::engine::general_purpose::STANDARD.encode("admin:pw");
        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, format!("Basic {v}").parse().unwrap());
        assert_eq!(
            basic_credentials(&h),
            Some(("admin".to_string(), "pw".to_string()))
        );
    }

    #[test]
    fn basic_credentials_keeps_password_colons() {
        // 密码里带冒号：只按第一个冒号切分
        let v = base64::engine::general_purpose::STANDARD.encode("admin:a:b:c");
        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, format!("Basic {v}").parse().unwrap());
        assert_eq!(
            basic_credentials(&h),
            Some(("admin".to_string(), "a:b:c".to_string()))
        );
    }

    #[test]
    fn basic_credentials_rejects_garbage() {
        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, "Basic !!!".parse().unwrap());
        assert_eq!(basic_credentials(&h), None);
        assert_eq!(basic_credentials(&HeaderMap::new()), None);
        // Bearer 不该被当成 Basic
        let mut h2 = HeaderMap::new();
        h2.insert(header::AUTHORIZATION, "Bearer abc".parse().unwrap());
        assert_eq!(basic_credentials(&h2), None);
    }

    #[test]
    fn options_response_advertises_dav() {
        let r = options_response();
        assert_eq!(r.status(), StatusCode::OK);
        assert!(r.headers().get("allow").is_some());
        assert!(r.headers().get("accept-ranges").is_some());
    }

    #[test]
    fn href_encodes_each_segment() {
        assert_eq!(href_encode("/"), "/");
        assert_eq!(href_encode("/a/b"), "/a/b");
        assert_eq!(
            href_encode("/账号 名/a&b/中文.mp3"),
            "/%E8%B4%A6%E5%8F%B7%20%E5%90%8D/a%26b/%E4%B8%AD%E6%96%87.mp3"
        );
        // 引号与 & 必须编码（href 要同时过 XML 与客户端解析）
        assert_eq!(href_encode("/it's"), "/it%27s");
        assert_eq!(href_encode("/x'y"), "/x%27y");
    }

    #[test]
    fn xml_escape_covers_five_entities() {
        assert_eq!(xml_escape("a<b>&\"'"), "a&lt;b&gt;&amp;&quot;&apos;");
        assert_eq!(xml_escape("正常"), "正常");
    }

    #[test]
    fn http_date_is_rfc1123_gmt() {
        // 1700000000000 ms = 2023-11-14T22:13:20Z（周二）
        assert_eq!(
            http_date(1_700_000_000_000),
            "Tue, 14 Nov 2023 22:13:20 GMT"
        );
        // 毫秒部分不影响秒级格式
        assert_eq!(
            http_date(1_700_000_000_999),
            "Tue, 14 Nov 2023 22:13:20 GMT"
        );
    }

    #[test]
    fn iso8601_is_utc_seconds() {
        assert_eq!(iso8601(1_700_000_000_000), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn parse_depth_caps_infinity() {
        assert_eq!(parse_depth(Some("0")), 0);
        assert_eq!(parse_depth(Some("1")), 1);
        assert_eq!(parse_depth(Some("infinity")), 1);
        assert_eq!(parse_depth(None), 1);
        assert_eq!(parse_depth(Some(" 0 ")), 0);
    }

    #[test]
    fn etag_prefers_driver_value() {
        let mut e = Entry {
            size: 12,
            updated_at: Some(1_700_000_000_000),
            ..Default::default()
        };
        assert_eq!(etag_of(&e), "\"12-1700000000000\"");
        e.etag = Some("abc".to_string());
        assert_eq!(etag_of(&e), "\"abc\"");
        e.etag = Some("\"abc\"".to_string());
        assert_eq!(etag_of(&e), "\"abc\"");
    }

    #[test]
    fn href_for_marks_collections_with_slash() {
        assert_eq!(href_for("/", true), "/dav/");
        assert_eq!(href_for("/账号", true), "/dav/%E8%B4%A6%E5%8F%B7/");
        assert_eq!(
            href_for("/账号/a.mp3", false),
            "/dav/%E8%B4%A6%E5%8F%B7/a.mp3"
        );
    }

    #[test]
    fn propfind_response_carries_dir_and_file_props() {
        let dir = Entry {
            name: "音乐".to_string(),
            is_dir: true,
            ..Default::default()
        };
        let x = propfind_response("/dav/%E9%9F%B3%E4%B9%90/", &dir);
        assert!(x.contains("<D:collection/>"));
        assert!(x.contains("<D:displayname>音乐</D:displayname>"));
        assert!(!x.contains("getcontentlength"));

        let file = Entry {
            name: "a<b.mp3".to_string(),
            size: 4096,
            updated_at: Some(1_700_000_000_000),
            ..Default::default()
        };
        let y = propfind_response("/dav/a%3Cb.mp3", &file);
        assert!(y.contains("<D:getcontentlength>4096</D:getcontentlength>"));
        assert!(y.contains("<D:getcontenttype>audio/mpeg</D:getcontenttype>"));
        assert!(y.contains("<D:getlastmodified>Tue, 14 Nov 2023 22:13:20 GMT</D:getlastmodified>"));
        assert!(y.contains("<D:creationdate>2023-11-14T22:13:20Z</D:creationdate>"));
        // 名字里的 < 必须转义，否则 XML 直接坏掉
        assert!(y.contains("<D:displayname>a&lt;b.mp3</D:displayname>"));
    }

    #[test]
    fn multistatus_wraps_responses() {
        let body = multistatus(&[propfind_response("/dav/", &Entry::default())]);
        assert!(body.starts_with("<?xml version=\"1.0\" encoding=\"utf-8\"?>"));
        assert!(body.contains("xmlns:D=\"DAV:\""));
        assert!(body.ends_with("</D:multistatus>"));
        assert_eq!(body.matches("<D:response>").count(), 1);
    }

    #[test]
    fn head_response_reports_metadata() {
        let e = Entry {
            name: "song.mp3".to_string(),
            size: 5_219_003,
            updated_at: Some(1_700_000_000_000),
            ..Default::default()
        };
        let r = head_response(&e);
        assert_eq!(r.status(), StatusCode::OK);
        let h = r.headers();
        assert_eq!(h.get(header::CONTENT_LENGTH).unwrap(), "5219003");
        assert_eq!(h.get(header::CONTENT_TYPE).unwrap(), "audio/mpeg");
        assert_eq!(h.get(header::ACCEPT_RANGES).unwrap(), "bytes");
        assert_eq!(
            h.get(header::LAST_MODIFIED).unwrap(),
            "Tue, 14 Nov 2023 22:13:20 GMT"
        );
        assert_eq!(h.get(header::ETAG).unwrap(), "\"5219003-1700000000000\"");
    }

    #[test]
    fn split_parent_rejects_virtual_root() {
        assert_eq!(split_parent("/a"), None);
        assert_eq!(split_parent("/"), None);
        assert_eq!(
            split_parent("/acc/dir/f.mp3"),
            Some(("/acc/dir".to_string(), "f.mp3".to_string()))
        );
        assert_eq!(
            split_parent("/acc/f.mp3"),
            Some(("/acc".to_string(), "f.mp3".to_string()))
        );
    }

    #[test]
    fn destination_accepts_path_and_url() {
        assert_eq!(dav_destination("/dav/a/b.mp3", None).unwrap(), "/a/b.mp3");
        assert_eq!(
            dav_destination(
                "http://127.0.0.1:5244/dav/a/%E4%B8%AD.mp3",
                Some("127.0.0.1:5244")
            )
            .unwrap(),
            "/a/中.mp3"
        );
        // 主机不匹配 / 缺主机段 → 拒绝
        assert_eq!(
            dav_destination("http://other:5244/dav/a", Some("127.0.0.1:5244")),
            None
        );
        assert_eq!(dav_destination("http://127.0.0.1:5244", None), None);
        // 带查询串也剥掉
        assert_eq!(dav_destination("/dav/a/b?x=1", None).unwrap(), "/a/b");
    }

    #[test]
    fn timeout_parsing_is_clamped() {
        let mut h = HeaderMap::new();
        h.insert("timeout", "Second-120".parse().unwrap());
        assert_eq!(parse_timeout(&h), 120);
        h.insert("timeout", "Infinite".parse().unwrap());
        assert_eq!(parse_timeout(&h), 3600);
        h.insert("timeout", "Second-99999999".parse().unwrap());
        assert_eq!(parse_timeout(&h), 7 * 24 * 3600);
        h.insert("timeout", "Second-10".parse().unwrap());
        assert_eq!(parse_timeout(&h), 60);
    }

    #[test]
    fn locks_roundtrip_and_sweep() {
        let token = "opaquelocktoken:test-roundtrip";
        {
            let mut m = locks().lock().unwrap();
            m.insert(
                token.to_string(),
                LockEntry {
                    path: "/a".to_string(),
                    expires: std::time::Instant::now() + std::time::Duration::from_secs(60),
                },
            );
        }
        // 过期条目会被清理
        {
            let mut m = locks().lock().unwrap();
            m.insert(
                "opaquelocktoken:expired".to_string(),
                LockEntry {
                    path: "/b".to_string(),
                    expires: std::time::Instant::now() - std::time::Duration::from_secs(1),
                },
            );
            sweep_locks(&mut m);
            assert!(m.contains_key(token));
            assert!(!m.contains_key("opaquelocktoken:expired"));
            m.remove(token);
        }
    }

    #[test]
    fn activelock_xml_has_token_and_timeout() {
        let x = activelock_xml("opaquelocktoken:abc", 1, 3600);
        assert!(x.contains("<D:write/>"));
        assert!(x.contains("<D:exclusive/>"));
        assert!(x.contains("<D:depth>1</D:depth>"));
        assert!(x.contains("<D:timeout>Second-3600</D:timeout>"));
        assert!(x.contains("opaquelocktoken:abc"));
    }

    #[test]
    fn driver_errors_map_to_status() {
        assert_eq!(
            map_driver_error("路径不存在: /x").status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            map_driver_error("网易云音乐为只读驱动，不支持此操作").status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            map_driver_error("cookie 已失效").status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            map_driver_error("连接超时").status(),
            StatusCode::BAD_GATEWAY
        );
    }
}
