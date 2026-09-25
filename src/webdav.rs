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
                return r;
            }
            match method.as_str() {
                "PROPFIND" => not_implemented(),
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
) -> Result<(), Response> {
    let now = std::time::Instant::now();
    if let Err(wait) = st.login_limiter.lock().unwrap().check(ip, now) {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            format!("认证失败次数过多，请 {} 秒后再试", wait.as_secs()),
        )
            .into_response());
    }

    // Bearer：面板会话 token（与 /d、/p 的会话鉴权同一套）
    if let Some(token) = crate::auth::token_from_headers(headers) {
        if st.session_valid(&token) {
            return Ok(());
        }
    }

    let Some((user, pass)) = basic_credentials(headers) else {
        return Err(unauthorized());
    };
    if crate::auth::verify_credentials(st, &user, &pass).await {
        st.login_limiter.lock().unwrap().record_success(ip);
        Ok(())
    } else {
        st.login_limiter.lock().unwrap().record_failure(ip, now);
        Err(unauthorized())
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
}
