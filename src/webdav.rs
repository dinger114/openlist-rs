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
use std::net::SocketAddr;

use crate::config::Entry;
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
    _body: Body,
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
                "GET" | "HEAD" => not_implemented(),
                "PUT" => not_implemented(),
                "MKCOL" => not_implemented(),
                "DELETE" => not_implemented(),
                "MOVE" | "COPY" => not_implemented(),
                "LOCK" => not_implemented(),
                "UNLOCK" => not_implemented(),
                "PROPPATCH" => not_implemented(),
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

fn not_implemented() -> Response {
    (StatusCode::NOT_IMPLEMENTED, "尚未实现").into_response()
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
