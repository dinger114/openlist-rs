mod api;
mod assets;
mod auth;
mod compat;
mod config;
mod drivers;
mod state;

use clap::Parser;
use state::AppState;
use axum::{
    routing::{delete, get, patch, post},
    Router,
};

// ---------- CLI ----------

#[derive(Parser, Debug)]
#[command(name = "openlist-mini", version, about = "OpenList Mini - 夸克/123 网盘浏览下载")]
struct Args {
    /// 监听地址：127.0.0.1 仅本机，0.0.0.0 局域网开放
    #[arg(short = 'a', long, default_value = "127.0.0.1")]
    addr: String,

    /// 监听端口
    #[arg(short = 'p', long, default_value_t = 5299)]
    port: u16,

    /// 数据目录（数据库 openlist.redb 与加密密钥 openlist.key 所在目录）
    #[arg(short = 'd', long, default_value = "data")]
    dir: String,

    /// 面板登录用户名（设置后启用鉴权；也可用环境变量 OPENLIST_WEB_USER）
    #[arg(long)]
    web_user: Option<String>,

    /// 面板登录密码（不传则随机生成并打印；也可用环境变量 OPENLIST_WEB_PASS）
    #[arg(long)]
    web_pass: Option<String>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let state = AppState::new(&args.dir, args.web_user.clone(), args.web_pass.clone());

    let app = Router::new()
        // 自有面板 API
        .route("/api/accounts", get(api::list_accounts).post(api::add_account))
        .route("/api/accounts/{id}", delete(api::del_account).put(api::edit_account))
        .route("/api/accounts/{id}/enabled", patch(api::patch_account_enabled))
        .route("/api/accounts/{id}/secret", get(api::get_account_secret))
        .route("/api/files", get(api::list_files))
        .route("/api/download", get(api::get_download))
        .route("/api/stream", get(api::stream_file))
        .route("/api/login", post(auth::login))
        .route("/api/logout", post(auth::logout))
        .route("/api/auth/status", get(auth::auth_status))
        // OpenList 官方 API 兼容层（NovaTV/TVBox 等 AList 协议客户端）
        .route("/api/auth/login", post(compat::compat_login))
        .route("/api/fs/list", post(compat::compat_fs_list))
        .route("/api/fs/get", post(compat::compat_fs_get))
        // 写操作（对齐 Go 版 OpenList 端点）
        .route("/api/fs/mkdir", post(compat::compat_fs_mkdir))
        .route("/api/fs/rename", post(compat::compat_fs_rename))
        .route("/api/fs/move", post(compat::compat_fs_move))
        .route("/api/fs/copy", post(compat::compat_fs_copy))
        .route("/api/fs/remove", post(compat::compat_fs_remove))
        .route("/api/fs/put", post(compat::compat_fs_put))
        .route("/api/fs/form", post(compat::compat_fs_form))
        .route("/api/fs/put/progress", get(compat::compat_fs_put_progress))
        .route("/d/{*path}", get(compat::compat_down))
        .route("/p/{*path}", get(compat::compat_proxy))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::auth_guard,
        ))
        .fallback(assets::serve_static)
        .with_state(state);

    let addr = format!("{}:{}", args.addr, args.port);
    println!("OpenList Mini 运行中: http://{addr}");
    println!("数据目录: {}", args.dir);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("监听 {addr} 失败: {e}"));
    axum::serve(listener, app).await.unwrap();
}
