use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    response::{IntoResponse, Response},
};

// rust-embed 编译期嵌入 web/dist，单二进制分发
#[derive(rust_embed::RustEmbed)]
#[folder = "web/dist"]
struct Assets;

fn mime_of(path: &str) -> &'static str {
    match path.rsplit('.').next() {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "application/javascript",
        Some("css") => "text/css",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("webp") => "image/webp",
        Some("ico") => "image/x-icon",
        Some("json") => "application/json",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    }
}

/// 静态文件 + SPA fallback
pub(crate) async fn serve_static(req: Request<Body>) -> Response {
    let raw = req.uri().path().trim_start_matches('/');
    // 无需清洗 `..`：rust-embed 的 Assets::get 是编译期嵌入表的精确键查找，
    // 不经过文件系统，天然没有穿越面。保留 replace 反而会掩盖真实路径。
    let path = if raw.is_empty() { "index.html" } else { raw };
    match Assets::get(path) {
        Some(f) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, mime_of(path))],
            f.data.into_owned(),
        )
            .into_response(),
        None => match Assets::get("index.html") {
            Some(f) => (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                f.data.into_owned(),
            )
                .into_response(),
            None => (
                StatusCode::NOT_FOUND,
                "前端资源未嵌入（构建时缺少 web/dist，先执行 cd web && npm install && npm run build）"
                    .to_string(),
            )
                .into_response(),
        },
    }
}
