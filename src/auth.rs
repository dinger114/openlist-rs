use crate::state::AppState;
use axum::{
    extract::State,
    http::{header, HeaderMap, Request, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;

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
        let valid = token
            .map(|t| st.sessions.lock().unwrap().contains(&t))
            .unwrap_or(false);
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

/// 签发会话 token 并注册到内存会话表
pub(crate) fn issue_session(st: &AppState) -> String {
    let token = uuid::Uuid::new_v4().to_string() + &uuid::Uuid::new_v4().simple().to_string();
    st.sessions.lock().unwrap().insert(token.clone());
    token
}

#[derive(Deserialize)]
pub(crate) struct LoginReq {
    username: String,
    password: String,
}

/// POST /api/login —— 面板登录（Cookie 会话）
pub(crate) async fn login(State(st): State<AppState>, Json(req): Json<LoginReq>) -> Response {
    let valid = {
        let auth = st.auth.read().unwrap();
        req.username == auth.user && req.password == auth.pass
    };
    if !valid {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "用户名或密码错误" })),
        )
            .into_response();
    }
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
        st.sessions.lock().unwrap().remove(&token);
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
    st.store
        .update_web_auth(user_ref.map(String::from), pass_ref.map(String::from))
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("保存失败: {e}")))?;
    {
        let mut auth = st.auth.write().unwrap();
        if let Some(u) = user_ref {
            auth.user = u.to_string();
        }
        if let Some(p) = pass_ref {
            auth.pass = p.to_string();
        }
    }
    st.sessions.lock().unwrap().clear();
    Ok(Json(json!({ "ok": true })))
}
