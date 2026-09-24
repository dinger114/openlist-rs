mod api;
mod assets;
mod auth;
mod compat;
mod config;
mod drivers;
mod sign;
mod state;

use axum::{
    routing::{delete, get, patch, post},
    Router,
};
use clap::{Parser, Subcommand};
use state::AppState;
use std::io::{BufRead, Write};

// ---------- CLI ----------

#[derive(Parser, Debug)]
#[command(
    name = "openlist-rs",
    version,
    about = "OpenList Rust 版 - 多网盘浏览下载"
)]
struct Args {
    /// 监听地址：默认仅本机（127.0.0.1）；要局域网访问用 0.0.0.0
    #[arg(short = 'a', long, default_value = "127.0.0.1")]
    addr: String,

    /// 监听端口
    #[arg(short = 'p', long, default_value_t = 5244)]
    port: u16,

    /// 数据目录（数据库 openlist.redb 与加密密钥 openlist.key 所在目录）
    #[arg(short = 'd', long, default_value = "data", global = true)]
    dir: String,

    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// 重置面板账号为 admin，密码随机生成替换数据库并打印到终端
    ResetUser,
    /// 交互式设置面板登录用户名（替换数据库中的账号）
    SetAccount,
    /// 交互式设置面板登录密码（替换数据库中的密码）
    SetPassword,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // 账号管理子命令：操作数据库后直接退出，不启动服务
    if let Some(cmd) = args.cmd {
        run_command(cmd, &args.dir);
        return;
    }

    let state = AppState::new(&args.dir);

    let app = Router::new()
        // 自有面板 API
        .route(
            "/api/accounts",
            get(api::list_accounts).post(api::add_account),
        )
        .route(
            "/api/accounts/{id}",
            delete(api::del_account).put(api::edit_account),
        )
        .route(
            "/api/accounts/{id}/enabled",
            patch(api::patch_account_enabled),
        )
        .route("/api/accounts/{id}/secret", get(api::get_account_secret))
        .route("/api/files", get(api::list_files))
        .route("/api/download", get(api::get_download))
        .route("/api/stream", get(api::stream_file))
        .route("/api/login", post(auth::login))
        .route("/api/logout", post(auth::logout))
        .route("/api/auth/status", get(auth::auth_status))
        // 面板账号设置（设置页）
        .route("/api/web/user", get(auth::get_web_user))
        .route("/api/web/settings", post(auth::update_web_settings))
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
        // 上传没有体量上限：/api/fs/form 是 multipart 提取器，axum 默认 2MB 上限会让稍大的
        // 文件直接 400（"Error parsing multipart/form-data request"）；内容由 handler 边收边落盘，
        // /api/fs/put 本来就是流式，不受上限保护也无需它
        .layer(axum::extract::DefaultBodyLimit::disable())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::auth_guard,
        ))
        .fallback(assets::serve_static)
        .with_state(state);

    let addr = format!("{}:{}", args.addr, args.port);
    println!("OpenList 运行中: http://{addr}");
    if !is_loopback(&args.addr) {
        // /d、/p 是免登录下载端点，靠链接签名保护（见 src/sign.rs）。
        // 绑到非本机地址等于把已配置的网盘暴露给网络可达者，这里显式提醒。
        println!(
            "提醒: 已监听 {addr}（非仅本机），/d、/p 下载端点对网络可达者开放；\
             请确认面板密码不是默认值，必要时用防火墙/反代限制来源"
        );
    }
    println!("数据目录: {}", args.dir);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("监听 {addr} 失败: {e}"));
    axum::serve(listener, app).await.unwrap();
}

/// 是否仅本机监听（127.0.0.0/8、::1、localhost）
fn is_loopback(addr: &str) -> bool {
    matches!(addr, "localhost" | "::1" | "[::1]")
        || addr
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
}

fn run_command(cmd: Cmd, dir: &str) {
    match cmd {
        Cmd::ResetUser => {
            let store = config::Store::load(dir);
            let pass = state::random_password();
            store
                .update_web_auth(Some("admin".to_string()), Some(pass.clone()))
                .unwrap_or_else(|e| panic!("写入数据库失败: {e}"));
            println!("面板账号已重置");
            println!("用户名: admin");
            println!("密码: {pass}");
        }
        Cmd::SetAccount => {
            let user = prompt_input("请输入新的面板用户名: ");
            let store = config::Store::load(dir);
            // 数据库尚无密码时补一个随机密码，避免出现“有账号无密码”
            let need_pass = {
                let data = store.data.lock().unwrap();
                data.web_pass.as_deref().map(str::is_empty).unwrap_or(true)
            };
            let pass = if need_pass {
                let p = state::random_password();
                println!("数据库未设置密码，已生成随机密码: {p}");
                Some(p)
            } else {
                None
            };
            store
                .update_web_auth(Some(user), pass)
                .unwrap_or_else(|e| panic!("写入数据库失败: {e}"));
            println!("面板用户名已更新");
        }
        Cmd::SetPassword => {
            let pass = prompt_input("请输入新的面板密码: ");
            let store = config::Store::load(dir);
            // 数据库尚无账号时补默认 admin，避免出现“有密码无账号”
            let need_user = {
                let data = store.data.lock().unwrap();
                data.web_user.as_deref().map(str::is_empty).unwrap_or(true)
            };
            let user = if need_user {
                println!("数据库未设置用户名，已设置为: admin");
                Some("admin".to_string())
            } else {
                None
            };
            store
                .update_web_auth(user, Some(pass))
                .unwrap_or_else(|e| panic!("写入数据库失败: {e}"));
            println!("面板密码已更新");
        }
    }
}

/// 读取一行终端输入（去除首尾空白），空输入报错退出
fn prompt_input(prompt: &str) -> String {
    print!("{prompt}");
    std::io::stdout().flush().unwrap();
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .unwrap_or_else(|e| panic!("读取输入失败: {e}"));
    let trimmed = line.trim().to_string();
    if trimmed.is_empty() {
        panic!("输入不能为空");
    }
    trimmed
}
