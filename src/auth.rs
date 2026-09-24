use crate::state::AppState;
use axum::{
    extract::{ConnectInfo, State},
    http::{header, HeaderMap, Request, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;
use std::time::Instant;

/// axum 中间件：/api/*（除登录与状态接口）要求有效会话。
/// 面板走 Cookie；OpenList 协议客户端（NovaTV/TVBox）走 Authorization 头。
pub(crate) async fn auth_guard(
    State(st): State<AppState>,
    req: Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Response {
    let path = req.uri().path();
    if path.starts_with("/api")
        && path != "/api/login"
        && path != "/api/auth/login"
        && path != "/api/auth/status"
    {
        let token = extract_token(&req);
        // 会话校验带 TTL 与滑动续期（见 state::SESSION_TTL）；过期条目会被顺手删除
        let valid = token.map(|t| st.session_valid(&t)).unwrap_or(false);
        if !valid {
            // OpenList 协议客户端（/api/fs/*）习惯 HTTP200 + code 包装；
            // 自有面板 API 保持标准 HTTP 401
            if path.starts_with("/api/fs") {
                let body =
                    Json(json!({ "code": 401, "message": "token is invalid", "data": null }));
                return (StatusCode::OK, body).into_response();
            }
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "未登录或会话已过期" })),
            )
                .into_response();
        }
    }
    next.run(req).await
}

fn extract_token(req: &Request<axum::body::Body>) -> Option<String> {
    token_from_headers(req.headers())
}

/// 从请求头取会话 token：面板走 Cookie（olm_token），
/// OpenList 协议客户端（NovaTV/TVBox）走 Authorization 头。
/// /d、/p 的下载鉴权复用同一套（见 compat::authorize_download）。
pub(crate) fn token_from_headers(headers: &HeaderMap) -> Option<String> {
    let cookie_token = headers
        .get(header::COOKIE)
        .and_then(|c| c.to_str().ok())
        .and_then(|c| parse_cookie_value(c, "olm_token"));
    cookie_token.or_else(|| {
        headers
            .get(header::AUTHORIZATION)
            .and_then(|a| a.to_str().ok())
            .map(|a| a.trim().trim_start_matches("Bearer ").trim().to_string())
            .filter(|t| !t.is_empty())
    })
}

pub(crate) fn parse_cookie_value(cookie_header: &str, name: &str) -> Option<String> {
    for pair in cookie_header.split(';') {
        let mut it = pair.trim().splitn(2, '=');
        if it.next()? == name {
            return it.next().map(|v| v.trim().to_string());
        }
    }
    None
}

/// 生成会话 token 并登记（TTL / 滑动续期由 AppState 管）
pub(crate) fn issue_session(st: &AppState) -> String {
    let token = uuid::Uuid::new_v4().to_string() + &uuid::Uuid::new_v4().simple().to_string();
    st.issue_session(token.clone());
    token
}

/// 在阻塞线程池里跑密码哈希/校验，并受并发闸门限制。
///
/// argon2 是同步的 CPU+内存密集计算（默认参数每次 19MiB）：既不能堵住 async worker，
/// 也不能不限并发 —— 否则登录洪水能用 19MiB/请求把内存打满。
pub(crate) async fn run_password_task<F, T>(st: &AppState, f: F) -> Result<T, String>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let permit = st
        .password_gate
        .clone()
        .acquire_owned()
        .await
        .map_err(|e| format!("密码计算排队失败: {e}"))?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        f()
    })
    .await
    .map_err(|e| format!("密码计算失败: {e}"))
}

/// 校验面板账号密码（面板 `/api/login` 与协议 `/api/auth/login` 共用）。
///
/// - 库里是 PHC 串 → argon2 verify；还是明文（老库 / 被旧版本写回）→ 定长比较
/// - 密码正确但库里是明文或参数过期 → 顺手把新哈希写回数据库与内存
/// - 用户名不符也照跑哈希：避免「响应快 = 用户名不对」这种时序侧信道
pub(crate) async fn verify_credentials(st: &AppState, user: &str, plain: &str) -> bool {
    let (stored_user, stored_pass) = {
        let auth = st.auth.read().unwrap();
        (auth.user.clone(), auth.pass.clone())
    };
    let plain_owned = plain.to_string();
    let outcome = match run_password_task(st, move || {
        crate::password::verify_password(&stored_pass, &plain_owned)
    })
    .await
    {
        Ok(o) => o,
        Err(e) => {
            eprintln!("密码校验失败: {e}");
            return false;
        }
    };
    if !outcome.ok || user != stored_user {
        return false;
    }
    if outcome.needs_rehash {
        let plain_owned = plain.to_string();
        match run_password_task(st, move || crate::password::hash_password(&plain_owned)).await {
            Ok(Ok(hashed)) => {
                // 库与内存同步升级（update_web_auth 幂等，不会二次哈希）
                if let Err(e) = st.store.update_web_auth(None, Some(hashed.clone())) {
                    eprintln!("面板密码升级写入失败: {e}");
                }
                st.auth.write().unwrap().pass = hashed;
            }
            Ok(Err(e)) => eprintln!("面板密码升级哈希失败: {e}"),
            Err(e) => eprintln!("面板密码升级失败: {e}"),
        }
    }
    true
}

/// 登录失败限速统一的 429 响应（带 Retry-After）
fn rate_limited(wait: std::time::Duration) -> Response {
    let secs = wait.as_secs().max(1);
    let mut resp = (
        StatusCode::TOO_MANY_REQUESTS,
        Json(json!({ "error": format!("登录失败次数过多，请 {secs} 秒后再试") })),
    )
        .into_response();
    if let Ok(v) = header::HeaderValue::from_str(&secs.to_string()) {
        resp.headers_mut().insert(header::RETRY_AFTER, v);
    }
    resp
}

#[derive(Deserialize)]
pub(crate) struct LoginReq {
    username: String,
    password: String,
}

/// POST /api/login —— 面板登录（Cookie 会话）
///
/// 按 TCP 对端 IP 做失败限速（连错 5 次锁 60 秒，之后翻倍，上限 15 分钟），
/// 命中限速回 429 + Retry-After。
pub(crate) async fn login(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(req): Json<LoginReq>,
) -> Response {
    let ip = peer.ip();
    let now = Instant::now();
    if let Err(wait) = st.login_limiter.lock().unwrap().check(ip, now) {
        return rate_limited(wait);
    }
    if !verify_credentials(&st, &req.username, &req.password).await {
        st.login_limiter.lock().unwrap().record_failure(ip, now);
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "用户名或密码错误" })),
        )
            .into_response();
    }
    st.login_limiter.lock().unwrap().record_success(ip);
    let token = issue_session(&st);
    let mut resp = Json(json!({ "ok": true })).into_response();
    resp.headers_mut().insert(
        header::SET_COOKIE,
        header::HeaderValue::from_str(&format!(
            "olm_token={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800"
        ))
        .unwrap(),
    );
    resp
}

/// POST /api/logout —— 面板登出
pub(crate) async fn logout(State(st): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(token) = headers
        .get(header::COOKIE)
        .and_then(|c| c.to_str().ok())
        .and_then(|c| parse_cookie_value(c, "olm_token"))
    {
        st.drop_session(&token);
    }
    let mut resp = Json(json!({ "ok": true })).into_response();
    resp.headers_mut().insert(
        header::SET_COOKIE,
        header::HeaderValue::from_static("olm_token=; Path=/; HttpOnly; Max-Age=0"),
    );
    resp
}

/// GET /api/auth/status —— 鉴权始终启用（保留端点供前端判断登出按钮）
pub(crate) async fn auth_status() -> Json<serde_json::Value> {
    Json(json!({ "enabled": true }))
}

/// GET /api/web/user —— 当前面板登录用户名（设置页回填）
pub(crate) async fn get_web_user(State(st): State<AppState>) -> Json<serde_json::Value> {
    Json(json!({ "username": st.auth.read().unwrap().user }))
}

#[derive(Deserialize)]
pub(crate) struct WebSettingsReq {
    username: Option<String>,
    password: Option<String>,
}

/// POST /api/web/settings —— 修改面板用户名/密码（None = 保持不变）。
/// 成功后同步内存凭据并清空全部会话，所有端需重新登录。
pub(crate) async fn update_web_settings(
    State(st): State<AppState>,
    Json(req): Json<WebSettingsReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let user_ref = req
        .username
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let pass_ref = req
        .password
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if user_ref.is_none() && pass_ref.is_none() {
        return Err((StatusCode::BAD_REQUEST, "用户名和密码均未填写".to_string()));
    }
    // 密码先算好哈希（同步 argon2 走阻塞池 + 并发闸门），库与内存都只存哈希
    let new_pass = match pass_ref {
        Some(p) => {
            let p_owned = p.to_string();
            Some(
                run_password_task(&st, move || crate::password::hash_password(&p_owned))
                    .await
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?,
            )
        }
        None => None,
    };
    st.store
        .update_web_auth(user_ref.map(String::from), new_pass.clone())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("保存失败: {e}")))?;
    {
        let mut auth = st.auth.write().unwrap();
        if let Some(u) = user_ref {
            auth.user = u.to_string();
        }
        if let Some(p) = new_pass {
            auth.pass = p;
        }
    }
    // 改密码后所有会话失效（含别的端点）
    st.clear_sessions();
    Ok(Json(json!({ "ok": true })))
}
