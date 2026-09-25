use crate::config::{Account, Credential, Entry};
use crate::drivers::Driver;
use crate::state::AppState;
use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::Response,
    Json,
};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;

/// 从 query string 中读取 JSON 字符串并反序列化为 Value。
/// axum Query 提取器把 URL 参数当纯字符串，所以需要手动 parse。
fn deserialize_json_str<'de, D>(deserializer: D) -> Result<Option<Value>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: Option<String> = Option::deserialize(deserializer)?;
    match s {
        None => Ok(None),
        Some(ref raw) if raw.is_empty() => Ok(None),
        Some(raw) => serde_json::from_str(&raw)
            .map(Some)
            .map_err(serde::de::Error::custom),
    }
}

// ---------- 账号管理 ----------

/// 驱动展示名
pub(crate) fn driver_display_name(kind: &str) -> &'static str {
    match kind {
        "quark" => "夸克网盘",
        "quark_uc" => "UC 网盘",
        "123pan" => "123 网盘",
        "aliyundrive_open" => "阿里云盘",
        "baidu_netdisk" => "百度网盘",
        "pan115" => "115 网盘",
        "thunder" => "迅雷网盘",
        "lanzou" => "蓝奏云",
        "pan139" => "移动云盘",
        "cloud189" => "天翼云盘",
        "local" => "本机存储",
        "webdav" => "WebDAV",
        "123pan_share" => "123 分享",
        "weiyun" => "腾讯微云",
        "onedrive" => "OneDrive",
        "google_drive" => "谷歌云盘",
        "s3" => "S3",
        "sftp" => "SFTP",
        "ftp" => "FTP",
        "smb" => "SMB",
        "alist_v3" => "AList V3",
        "github_releases" => "GitHub Releases",
        "pikpak" => "PikPak",
        "pikpak_share" => "PikPak 分享",
        "onedrive_app" => "OneDrive APP",
        "onedrive_share" => "OneDrive 分享",
        "dropbox" => "Dropbox",
        "google_photo" => "Google Photos",
        "openlist" => "OpenList",
        "openlist_share" => "OpenList 分享",
        "virtual" => "虚拟存储",
        "bunny" => "BunnyCDN",
        "yandex_disk" => "Yandex.Disk",
        "seafile" => "Seafile",
        "kodbox" => "可道云",
        "cloudreve_v4" => "Cloudreve V4",
        "terabox" => "Terabox",
        "ilanzou" => "蓝奏云优创",
        "halalcloud_open" => "halalcloud",
        "netease_music" => "网易云音乐",
        _ => "网盘",
    }
}

/// 各驱动的默认根目录 fid（对齐 Go 版各驱动 meta.go 的 DefaultRoot）
pub(crate) fn default_root_fid(driver_kind: &str, cred: &Credential) -> String {
    match driver_kind {
        "pan139" => "/".into(),
        "cloud189" => "-11".into(),
        "local" => match cred {
            Credential::Local { root_path } => root_path.clone(),
            _ => String::new(),
        },
        "webdav" => "/".into(),
        "s3" | "sftp" | "ftp" | "alist_v3" | "github_releases" | "onedrive_app"
        | "pikpak_share" => "/".into(),
        "openlist" | "openlist_share" | "virtual" | "bunny" | "yandex_disk" | "seafile"
        | "kodbox" | "cloudreve_v4" | "terabox" => "/".into(),
        "ilanzou" => match cred {
            Credential::Ilanzou { root_folder_id, .. } => {
                if root_folder_id.is_empty() {
                    "0".into()
                } else {
                    root_folder_id.clone()
                }
            }
            _ => "0".into(),
        },
        "smb" => ".".into(),
        "123pan_share" => "0".into(),
        "weiyun" => String::new(),
        // OneDrive 根目录为配置的 root_path（Go 版 DefaultRoot "/" + RootFolderPath）
        "onedrive" => match cred {
            Credential::Onedrive { root_path, .. } => {
                if root_path.is_empty() {
                    "/".into()
                } else {
                    root_path.clone()
                }
            }
            _ => "/".into(),
        },
        // Google Drive 根目录为配置的 root_folder_id（Go 版 DefaultRoot "root"）
        "google_drive" => match cred {
            Credential::GoogleDrive { root_folder_id, .. } => {
                if root_folder_id.is_empty() {
                    "root".into()
                } else {
                    root_folder_id.clone()
                }
            }
            _ => "root".into(),
        },
        // 阿里云盘开放平台根目录固定为 "root"，传 "0" 会 Bad Request
        "aliyundrive_open" => "root".into(),
        "baidu_netdisk" => "/".into(),
        "lanzou" => "-1".into(),
        "halalcloud_open" => "/".into(),
        "netease_music" => "/".into(),
        _ => "0".into(),
    }
}

#[derive(Serialize)]
struct AccountView {
    id: String,
    name: String,
    driver: String,
    server_proxy: bool,
    enabled: bool,
}

/// GET /api/accounts
pub(crate) async fn list_accounts(State(st): State<AppState>) -> Json<Value> {
    let data = st.store.data.lock().unwrap();
    let accounts: Vec<AccountView> = data
        .accounts
        .iter()
        .map(|a| AccountView {
            id: a.id.clone(),
            name: a.name.clone(),
            driver: match a.cred {
                Credential::Quark { .. } => "quark".into(),
                Credential::QuarkUC { .. } => "quark_uc".into(),
                Credential::Pan123 { .. } => "123pan".into(),
                Credential::AliyundriveOpen { .. } => "aliyundrive_open".into(),
                Credential::BaiduNetdisk { .. } => "baidu_netdisk".into(),
                Credential::Pan115 { .. } => "pan115".into(),
                Credential::Thunder { .. } => "thunder".into(),
                Credential::Lanzou { .. } => "lanzou".into(),
                Credential::Yun139 { .. } => "pan139".into(),
                Credential::Cloud189 { .. } => "cloud189".into(),
                Credential::Local { .. } => "local".into(),
                Credential::Webdav { .. } => "webdav".into(),
                Credential::Pan123Share { .. } => "123pan_share".into(),
                Credential::Weiyun { .. } => "weiyun".into(),
                Credential::Onedrive { .. } => "onedrive".into(),
                Credential::GoogleDrive { .. } => "google_drive".into(),
                Credential::S3 { .. } => "s3".into(),
                Credential::Sftp { .. } => "sftp".into(),
                Credential::Ftp { .. } => "ftp".into(),
                Credential::Smb { .. } => "smb".into(),
                Credential::AlistV3 { .. } => "alist_v3".into(),
                Credential::GithubReleases { .. } => "github_releases".into(),
                Credential::PikPak { .. } => "pikpak".into(),
                Credential::OnedriveShare { .. } => "onedrive_share".into(),
                Credential::Dropbox { .. } => "dropbox".into(),
                Credential::GooglePhoto { .. } => "google_photo".into(),
                Credential::Pan115Open { .. } => "pan115_open".into(),
                Credential::Pan115Share { .. } => "pan115_share".into(),
                Credential::Pan123Open { .. } => "pan123_open".into(),
                Credential::Pan123Link { .. } => "pan123_link".into(),
                Credential::Aliyundrive { .. } => "aliyundrive".into(),
                Credential::AliyundriveShare { .. } => "aliyundrive_share".into(),
                Credential::QuarkOpen { .. } => "quark_open".into(),
                Credential::QuarkTv { .. } => "quark_tv".into(),
                Credential::UcTv { .. } => "uc_tv".into(),
                Credential::PikPakShare { .. } => "pikpak_share".into(),
                Credential::OnedriveApp { .. } => "onedrive_app".into(),
                Credential::Openlist { .. } => "openlist".into(),
                Credential::OpenlistShare { .. } => "openlist_share".into(),
                Credential::Virtual { .. } => "virtual".into(),
                Credential::Bunny { .. } => "bunny".into(),
                Credential::YandexDisk { .. } => "yandex_disk".into(),
                Credential::Seafile { .. } => "seafile".into(),
                Credential::Kodbox { .. } => "kodbox".into(),
                Credential::CloudreveV4 { .. } => "cloudreve_v4".into(),
                Credential::Terabox { .. } => "terabox".into(),
                Credential::Ilanzou { .. } => "ilanzou".into(),
                Credential::HalalcloudOpen { .. } => "halalcloud_open".into(),
                Credential::NeteaseMusic { .. } => "netease_music".into(),
            },
            server_proxy: a.server_proxy,
            enabled: a.enabled,
        })
        .collect();
    Json(json!({ "accounts": accounts }))
}

#[derive(Deserialize)]
pub(crate) struct AddAccountReq {
    name: String,
    /// 网盘类型；缺省时按旧逻辑根据凭据字段推断（兼容旧前端）
    #[serde(default)]
    driver: Option<String>,
    // quark / quark_uc / pan115 / lanzou
    cookie: Option<String>,
    // 123pan / thunder
    username: Option<String>,
    password: Option<String>,
    // aliyundrive_open / baidu_netdisk
    refresh_token: Option<String>,
    // aliyundrive_open 可选：default / alipanTV
    #[serde(default)]
    alipan_type: Option<String>,
    // pan139：139 邮箱 Authorization（base64）
    #[serde(default)]
    authorization: Option<String>,
    // local：本机存储挂载目录
    #[serde(default)]
    root_path: Option<String>,
    // webdav：服务器地址（用户名/密码复用 username/password 字段）
    #[serde(default)]
    url: Option<String>,
    // 123pan_share：分享 key / 分享密码 / 可选 accesstoken
    #[serde(default)]
    share_key: Option<String>,
    #[serde(default)]
    share_pwd: Option<String>,
    #[serde(default)]
    access_token: Option<String>,
    // weiyun：登录 cookie
    #[serde(default)]
    cookies: Option<String>,
    // onedrive：region（global/cn/us/de），root_path 复用上面的字段
    #[serde(default)]
    region: Option<String>,
    // onedrive：true = SharePoint 站点模式（需配合 site_id）
    #[serde(default)]
    is_sharepoint: bool,
    // onedrive：SharePoint 站点 id
    #[serde(default)]
    site_id: Option<String>,
    // google_drive：根目录文件夹 id（默认 root）
    #[serde(default)]
    root_folder_id: Option<String>,
    // s3
    #[serde(default)]
    bucket: Option<String>,
    #[serde(default)]
    endpoint: Option<String>,
    #[serde(default)]
    access_key_id: Option<String>,
    #[serde(default)]
    secret_access_key: Option<String>,
    #[serde(default)]
    session_token: Option<String>,
    #[serde(default)]
    custom_host: Option<String>,
    #[serde(default)]
    force_path_style: Option<bool>,
    #[serde(default)]
    sign_url_expire: Option<u64>,
    // sftp
    #[serde(default)]
    private_key: Option<String>,
    #[serde(default)]
    passphrase: Option<String>,
    #[serde(default)]
    ignore_symlink_error: Option<bool>,
    // ftp
    #[serde(default)]
    encoding: Option<String>,
    #[serde(default)]
    cwd_list: Option<bool>,
    #[serde(default)]
    address: Option<String>,
    #[serde(default)]
    share_name: Option<String>,
    // alist_v3
    #[serde(default)]
    meta_password: Option<String>,
    #[serde(default)]
    token: Option<String>,
    // github_releases
    #[serde(default)]
    repo_structure: Option<String>,
    #[serde(default)]
    show_all_version: Option<bool>,
    #[serde(default)]
    show_source_code: Option<bool>,
    #[serde(default)]
    gh_proxy: Option<String>,
    #[serde(default)]
    per_page: Option<u32>,
    #[serde(default)]
    max_page: Option<u32>,
    // dropbox / google_photo / pikpak
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
    #[serde(default)]
    use_online_api: Option<bool>,
    #[serde(default)]
    device_id: Option<String>,
    // 115 share / 123 link / aliyun share / quark open
    // share_pwd 已在上方 123pan_share 段声明，勿重复
    #[serde(default)]
    share_code: Option<String>,
    #[serde(default)]
    receive_code: Option<String>,
    #[serde(default)]
    share_id: Option<String>,
    #[serde(default)]
    origin_urls: Option<String>,
    #[serde(default)]
    uid: Option<u64>,
    #[serde(default)]
    valid_duration: Option<i64>,
    #[serde(default)]
    app_id: Option<String>,
    #[serde(default)]
    sign_key: Option<String>,
    #[serde(default)]
    api_address: Option<String>,
    #[serde(default)]
    link_method: Option<String>,
    #[serde(default)]
    platform: Option<String>,
    #[serde(default)]
    use_transcoding_address: Option<bool>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    tenant_id: Option<String>,
    // ---- 新增驱动（openlist/virtual/bunny/yandex/seafile/kodbox/cloudreve/terabox/ilanzou） ----
    #[serde(default)]
    num_file: Option<u32>,
    #[serde(default)]
    num_folder: Option<u32>,
    #[serde(default)]
    repo_id: Option<String>,
    #[serde(default)]
    repo_pwd: Option<String>,
    #[serde(default)]
    site: Option<String>,
    #[serde(default)]
    download_api: Option<String>,

    /// 服务器代理开关（默认 false = 直链 302）
    #[serde(default)]
    server_proxy: bool,

    // halalcloud_open：API host 与超时（秒）
    // netease_music：云盘每页拉取条数（对齐上游 song_limit，默认 200；驱动按页拉全）
    #[serde(default)]
    song_limit: Option<u64>,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    timeout: Option<u64>,
}

/// POST /api/accounts —— 构建驱动验证凭据后保存
pub(crate) async fn add_account(
    State(st): State<AppState>,
    Json(req): Json<AddAccountReq>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let cookie = req
        .cookie
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let userpass = match (
        req.username.as_deref().map(str::trim),
        req.password.as_deref().map(str::trim),
    ) {
        (Some(u), Some(p)) if !u.is_empty() && !p.is_empty() => {
            Some((u.to_string(), p.to_string()))
        }
        _ => None,
    };
    let refresh = req
        .refresh_token
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    // 显式指定驱动优先，否则按凭据字段推断（旧逻辑）
    let kind = req
        .driver
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .or_else(|| {
            if cookie.is_some() {
                Some("quark".into())
            } else if userpass.is_some() {
                Some("123pan".into())
            } else {
                refresh.clone().map(|_| "aliyundrive_open".into())
            }
        })
        .ok_or((
            StatusCode::BAD_REQUEST,
            "缺少凭据：请按所选网盘类型填写对应参数".to_string(),
        ))?;

    let (driver_kind, cred) = match kind.as_str() {
        "quark" => (
            "quark",
            Credential::Quark {
                cookie: cookie.ok_or((StatusCode::BAD_REQUEST, "夸克需要 cookie".to_string()))?,
            },
        ),
        "quark_uc" | "uc" => (
            "quark_uc",
            Credential::QuarkUC {
                cookie: cookie
                    .ok_or((StatusCode::BAD_REQUEST, "UC 网盘需要 cookie".to_string()))?,
            },
        ),
        "123pan" => {
            let (u, p) =
                userpass.ok_or((StatusCode::BAD_REQUEST, "123 网盘需要账号密码".to_string()))?;
            (
                "123pan",
                Credential::Pan123 {
                    username: u,
                    password: p,
                    access_token: String::new(),
                    platform: "web".into(),
                },
            )
        }
        // 旧版 "aliyundrive" 走下方独立分支；开放平台仅匹配 open / aliyun 别名
        "aliyundrive_open" | "aliyun" => (
            "aliyundrive_open",
            Credential::AliyundriveOpen {
                refresh_token: refresh.ok_or((
                    StatusCode::BAD_REQUEST,
                    "阿里云盘需要 refresh_token".to_string(),
                ))?,
                access_token: String::new(),
                alipan_type: if req.alipan_type.as_deref() == Some("alipanTV") {
                    "alipanTV".into()
                } else {
                    "default".into()
                },
            },
        ),
        "baidu_netdisk" | "baidu" => (
            "baidu_netdisk",
            Credential::BaiduNetdisk {
                refresh_token: refresh.ok_or((
                    StatusCode::BAD_REQUEST,
                    "百度网盘需要 refresh_token".to_string(),
                ))?,
                access_token: String::new(),
            },
        ),
        "pan115" | "115" => (
            "pan115",
            Credential::Pan115 {
                cookie: cookie.ok_or((
                    StatusCode::BAD_REQUEST,
                    "115 网盘需要 cookie（含 UID/CID/SEID）".to_string(),
                ))?,
            },
        ),
        "thunder" | "xunlei" => {
            let (u, p) =
                userpass.ok_or((StatusCode::BAD_REQUEST, "迅雷网盘需要账号密码".to_string()))?;
            (
                "thunder",
                Credential::Thunder {
                    username: u,
                    password: p,
                    refresh_token: String::new(),
                    captcha_token: String::new(),
                    device_id: String::new(),
                },
            )
        }
        "lanzou" | "lanzouyun" => {
            let account = req.username.clone().unwrap_or_default().trim().to_string();
            let password = req.password.clone().unwrap_or_default();
            let cookie = req.cookie.clone().unwrap_or_default().trim().to_string();
            if account.is_empty() && cookie.is_empty() {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "蓝奏云需要账号密码或 cookie".to_string(),
                ));
            }
            (
                "lanzou",
                Credential::Lanzou {
                    cookie,
                    account,
                    password,
                },
            )
        }
        "pan139" | "139yun" | "mobile" => {
            let auth = req
                .authorization
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "移动云盘需要 139 Authorization".to_string(),
                ))?;
            (
                "pan139",
                Credential::Yun139 {
                    authorization: auth.to_string(),
                    drive_type: "personal_new".into(),
                },
            )
        }
        "cloud189" | "189" | "tianyi" => {
            let (u, p) =
                userpass.ok_or((StatusCode::BAD_REQUEST, "天翼云盘需要账号密码".to_string()))?;
            (
                "cloud189",
                Credential::Cloud189 {
                    username: u,
                    password: p,
                    cookie: String::new(),
                },
            )
        }
        "local" => {
            let root_path = req
                .root_path
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "本机存储需要挂载目录路径".to_string(),
                ))?;
            (
                "local",
                Credential::Local {
                    root_path: root_path.to_string(),
                },
            )
        }
        "webdav" => {
            let url = req
                .url
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((StatusCode::BAD_REQUEST, "WebDAV 需要服务器地址".to_string()))?;
            (
                "webdav",
                Credential::Webdav {
                    url: url.to_string(),
                    username: req.username.clone().unwrap_or_default(),
                    password: req.password.clone().unwrap_or_default(),
                    root_path: req
                        .root_path
                        .as_deref()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .unwrap_or("/")
                        .to_string(),
                },
            )
        }
        "123pan_share" | "123share" => {
            let share_key = req
                .share_key
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((StatusCode::BAD_REQUEST, "123 分享需要 shareKey".to_string()))?;
            (
                "123pan_share",
                Credential::Pan123Share {
                    share_key: share_key.to_string(),
                    share_pwd: req.share_pwd.clone().unwrap_or_default(),
                    access_token: req.access_token.clone().unwrap_or_default(),
                },
            )
        }
        "weiyun" => {
            let cookies = req
                .cookies
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "腾讯微云需要登录 cookie".to_string(),
                ))?;
            (
                "weiyun",
                Credential::Weiyun {
                    cookies: cookies.to_string(),
                    root_folder_id: String::new(),
                },
            )
        }
        "onedrive" => {
            let rt = refresh.ok_or((
                StatusCode::BAD_REQUEST,
                "OneDrive 需要 refresh_token".to_string(),
            ))?;
            (
                "onedrive",
                Credential::Onedrive {
                    region: req
                        .region
                        .as_deref()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .unwrap_or("global")
                        .to_string(),
                    is_sharepoint: req.is_sharepoint,
                    site_id: req.site_id.clone().unwrap_or_default(),
                    root_path: req
                        .root_path
                        .as_deref()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .unwrap_or("/")
                        .to_string(),
                    refresh_token: rt,
                    access_token: String::new(),
                },
            )
        }
        "google_drive" | "google" | "googledrive" => {
            let rt = refresh.ok_or((
                StatusCode::BAD_REQUEST,
                "Google Drive 需要 refresh_token".to_string(),
            ))?;
            (
                "google_drive",
                Credential::GoogleDrive {
                    refresh_token: rt,
                    access_token: String::new(),
                    root_folder_id: req.root_folder_id.clone().unwrap_or_default(),
                },
            )
        }

        "s3" => {
            let bucket = req
                .bucket
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((StatusCode::BAD_REQUEST, "S3 需要 bucket".to_string()))?;
            let endpoint = req
                .endpoint
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((StatusCode::BAD_REQUEST, "S3 需要 endpoint".to_string()))?;
            let access_key_id = req
                .access_key_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((StatusCode::BAD_REQUEST, "S3 需要 access_key_id".to_string()))?;
            let secret_access_key = req
                .secret_access_key
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "S3 需要 secret_access_key".to_string(),
                ))?;
            (
                "s3",
                Credential::S3 {
                    bucket: bucket.to_string(),
                    endpoint: endpoint.to_string(),
                    region: req.region.clone().unwrap_or_else(|| "us-east-1".into()),
                    access_key_id: access_key_id.to_string(),
                    secret_access_key: secret_access_key.to_string(),
                    session_token: req.session_token.clone().unwrap_or_default(),
                    custom_host: req.custom_host.clone().unwrap_or_default(),
                    force_path_style: req.force_path_style.unwrap_or(false),
                    sign_url_expire: req.sign_url_expire.unwrap_or(4),
                    root_path: req.root_path.clone().unwrap_or_else(|| "/".into()),
                },
            )
        }
        "sftp" => {
            let address = req
                .address
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((StatusCode::BAD_REQUEST, "SFTP 需要 address".to_string()))?;
            let username = req
                .username
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((StatusCode::BAD_REQUEST, "SFTP 需要 username".to_string()))?;
            (
                "sftp",
                Credential::Sftp {
                    address: address.to_string(),
                    username: username.to_string(),
                    password: req.password.clone().unwrap_or_default(),
                    private_key: req.private_key.clone().unwrap_or_default(),
                    passphrase: req.passphrase.clone().unwrap_or_default(),
                    root_path: req.root_path.clone().unwrap_or_else(|| "/".into()),
                    ignore_symlink_error: req.ignore_symlink_error.unwrap_or(false),
                },
            )
        }
        "ftp" => {
            let address = req
                .address
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((StatusCode::BAD_REQUEST, "FTP 需要 address".to_string()))?;
            let username = req
                .username
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((StatusCode::BAD_REQUEST, "FTP 需要 username".to_string()))?;
            let password = req.password.clone().unwrap_or_default();
            (
                "ftp",
                Credential::Ftp {
                    address: address.to_string(),
                    username: username.to_string(),
                    password,
                    encoding: req.encoding.clone().unwrap_or_default(),
                    root_path: req.root_path.clone().unwrap_or_else(|| "/".into()),
                    cwd_list: req.cwd_list.unwrap_or(false),
                },
            )
        }
        "smb" => {
            let address = req
                .address
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((StatusCode::BAD_REQUEST, "SMB 需要 address".to_string()))?;
            let username = req
                .username
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((StatusCode::BAD_REQUEST, "SMB 需要 username".to_string()))?;
            let share_name = req
                .share_name
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((StatusCode::BAD_REQUEST, "SMB 需要 share_name".to_string()))?;
            (
                "smb",
                Credential::Smb {
                    address: address.to_string(),
                    username: username.to_string(),
                    password: req.password.clone().unwrap_or_default(),
                    share_name: share_name.to_string(),
                    root_path: req.root_path.clone().unwrap_or_default(),
                },
            )
        }
        "alist_v3" => {
            let url = req
                .url
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((StatusCode::BAD_REQUEST, "AList V3 需要 url".to_string()))?;
            (
                "alist_v3",
                Credential::AlistV3 {
                    url: url.to_string(),
                    meta_password: req.meta_password.clone().unwrap_or_default(),
                    username: req.username.clone().unwrap_or_default(),
                    password: req.password.clone().unwrap_or_default(),
                    token: req.token.clone().unwrap_or_default(),
                },
            )
        }
        "github_releases" => {
            let repo_structure = req
                .repo_structure
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "GitHub Releases 需要 repo_structure".to_string(),
                ))?;
            (
                "github_releases",
                Credential::GithubReleases {
                    repo_structure: repo_structure.to_string(),
                    token: req.token.clone().unwrap_or_default(),
                    show_all_version: req.show_all_version.unwrap_or(false),
                    show_source_code: req.show_source_code.unwrap_or(false),
                    gh_proxy: req.gh_proxy.clone().unwrap_or_default(),
                    per_page: req.per_page.unwrap_or(30),
                    max_page: req.max_page.unwrap_or(0),
                },
            )
        }
        "pikpak" => {
            let username = req
                .username
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((StatusCode::BAD_REQUEST, "PikPak 需要 username".to_string()))?;
            let password = req.password.clone().unwrap_or_default();
            (
                "pikpak",
                Credential::PikPak {
                    username: username.to_string(),
                    password,
                    refresh_token: req.refresh_token.clone().unwrap_or_default(),
                    access_token: req.access_token.clone().unwrap_or_default(),
                    device_id: req.device_id.clone().unwrap_or_default(),
                },
            )
        }
        "onedrive_share" => {
            let url = req
                .url
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((StatusCode::BAD_REQUEST, "OneDrive 分享需要 url".to_string()))?;
            (
                "onedrive_share",
                Credential::OnedriveShare {
                    url: url.to_string(),
                    password: req.password.clone().unwrap_or_default(),
                },
            )
        }
        "dropbox" => {
            let refresh_token = req
                .refresh_token
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "Dropbox 需要 refresh_token".to_string(),
                ))?;
            (
                "dropbox",
                Credential::Dropbox {
                    refresh_token: refresh_token.to_string(),
                    access_token: req.access_token.clone().unwrap_or_default(),
                    root_path: req.root_path.clone().unwrap_or_default(),
                    use_online_api: req.use_online_api.unwrap_or(true),
                    client_id: req.client_id.clone().unwrap_or_default(),
                    client_secret: req.client_secret.clone().unwrap_or_default(),
                },
            )
        }
        "google_photo" => {
            let refresh_token = req
                .refresh_token
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "Google Photos 需要 refresh_token".to_string(),
                ))?;
            (
                "google_photo",
                Credential::GooglePhoto {
                    refresh_token: refresh_token.to_string(),
                    access_token: req.access_token.clone().unwrap_or_default(),
                    client_id: req.client_id.clone().unwrap_or_default(),
                    client_secret: req.client_secret.clone().unwrap_or_default(),
                },
            )
        }
        "pan115_open" | "115_open" => {
            let access_token = req.access_token.clone().unwrap_or_default();
            let refresh_token = req.refresh_token.clone().unwrap_or_default();
            if access_token.is_empty() && refresh_token.is_empty() {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "115 Open 需要 access_token 或 refresh_token".into(),
                ));
            }
            (
                "pan115_open",
                Credential::Pan115Open {
                    access_token,
                    refresh_token,
                },
            )
        }
        "pan115_share" | "115_share" => {
            let share_code = req
                .share_code
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "115 分享需要 share_code".to_string(),
                ))?;
            (
                "pan115_share",
                Credential::Pan115Share {
                    cookie: req.cookie.clone().unwrap_or_default(),
                    share_code: share_code.to_string(),
                    receive_code: req.receive_code.clone().unwrap_or_default(),
                },
            )
        }
        "pan123_open" | "123_open" => (
            "pan123_open",
            Credential::Pan123Open {
                client_id: req.client_id.clone().unwrap_or_default(),
                client_secret: req.client_secret.clone().unwrap_or_default(),
                refresh_token: req.refresh_token.clone().unwrap_or_default(),
                access_token: req.access_token.clone().unwrap_or_default(),
                use_online_api: req.use_online_api.unwrap_or(true),
                api_address: req.api_address.clone().unwrap_or_default(),
            },
        ),
        "pan123_link" | "123_link" => {
            let origin_urls = req
                .origin_urls
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "123PanLink 需要 origin_urls".to_string(),
                ))?;
            (
                "pan123_link",
                Credential::Pan123Link {
                    origin_urls: origin_urls.to_string(),
                    private_key: req.private_key.clone().unwrap_or_default(),
                    uid: req.uid.unwrap_or(0),
                    valid_duration: req.valid_duration.unwrap_or(30),
                },
            )
        }
        "aliyundrive" => {
            let refresh_token = req
                .refresh_token
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "阿里云盘(旧)需要 refresh_token".to_string(),
                ))?;
            (
                "aliyundrive",
                Credential::Aliyundrive {
                    refresh_token: refresh_token.to_string(),
                    access_token: req.access_token.clone().unwrap_or_default(),
                },
            )
        }
        "aliyundrive_share" => {
            let refresh_token = req
                .refresh_token
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "阿里分享需要 refresh_token".to_string(),
                ))?;
            let share_id = req
                .share_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((StatusCode::BAD_REQUEST, "阿里分享需要 share_id".to_string()))?;
            (
                "aliyundrive_share",
                Credential::AliyundriveShare {
                    refresh_token: refresh_token.to_string(),
                    access_token: req.access_token.clone().unwrap_or_default(),
                    share_id: share_id.to_string(),
                    share_pwd: req.share_pwd.clone().unwrap_or_default(),
                },
            )
        }
        "quark_open" => {
            let refresh_token = req
                .refresh_token
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "夸克 Open 需要 refresh_token".to_string(),
                ))?;
            let app_id = req
                .app_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((StatusCode::BAD_REQUEST, "夸克 Open 需要 app_id".to_string()))?;
            let sign_key = req
                .sign_key
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "夸克 Open 需要 sign_key".to_string(),
                ))?;
            (
                "quark_open",
                Credential::QuarkOpen {
                    refresh_token: refresh_token.to_string(),
                    access_token: req.access_token.clone().unwrap_or_default(),
                    app_id: app_id.to_string(),
                    sign_key: sign_key.to_string(),
                    use_online_api: req.use_online_api.unwrap_or(true),
                    api_address: req.api_address.clone().unwrap_or_default(),
                },
            )
        }
        "quark_tv" => (
            "quark_tv",
            Credential::QuarkTv {
                refresh_token: req.refresh_token.clone().unwrap_or_default(),
                access_token: req.access_token.clone().unwrap_or_default(),
                device_id: req.device_id.clone().unwrap_or_default(),
                link_method: req.link_method.clone().unwrap_or_else(|| "download".into()),
            },
        ),
        "uc_tv" => (
            "uc_tv",
            Credential::UcTv {
                refresh_token: req.refresh_token.clone().unwrap_or_default(),
                access_token: req.access_token.clone().unwrap_or_default(),
                device_id: req.device_id.clone().unwrap_or_default(),
                link_method: req.link_method.clone().unwrap_or_else(|| "download".into()),
            },
        ),

        "pikpak_share" => {
            let share_id = req
                .share_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "PikPak 分享需要 share_id".to_string(),
                ))?;
            (
                "pikpak_share",
                Credential::PikPakShare {
                    share_id: share_id.to_string(),
                    share_pwd: req.share_pwd.clone().unwrap_or_default(),
                    platform: req.platform.clone().unwrap_or_else(|| "web".into()),
                    device_id: req.device_id.clone().unwrap_or_default(),
                    use_transcoding_address: req.use_transcoding_address.unwrap_or(false),
                },
            )
        }
        "onedrive_app" => {
            let client_id = req
                .client_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "OneDrive APP 需要 client_id".to_string(),
                ))?;
            let client_secret = req
                .client_secret
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "OneDrive APP 需要 client_secret".to_string(),
                ))?;
            let email = req
                .email
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "OneDrive APP 需要用户邮箱 email".to_string(),
                ))?;
            (
                "onedrive_app",
                Credential::OnedriveApp {
                    region: req.region.clone().unwrap_or_else(|| "global".into()),
                    client_id: client_id.to_string(),
                    client_secret: client_secret.to_string(),
                    tenant_id: req.tenant_id.clone().unwrap_or_default(),
                    email: email.to_string(),
                    custom_host: req.custom_host.clone().unwrap_or_default(),
                    root_path: req.root_path.clone().unwrap_or_else(|| "/".into()),
                },
            )
        }
        "openlist" => {
            let url = req
                .url
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((StatusCode::BAD_REQUEST, "OpenList 需要 url".to_string()))?;
            (
                "openlist",
                Credential::Openlist {
                    url: url.to_string(),
                    meta_password: req.meta_password.clone().unwrap_or_default(),
                    username: req.username.clone().unwrap_or_default(),
                    password: req.password.clone().unwrap_or_default(),
                    token: req.token.clone().unwrap_or_default(),
                },
            )
        }
        "openlist_share" => {
            let url = req
                .url
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((StatusCode::BAD_REQUEST, "OpenList 分享需要 url".to_string()))?;
            let share_id = req
                .share_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "OpenList 分享需要 share_id".to_string(),
                ))?;
            (
                "openlist_share",
                Credential::OpenlistShare {
                    url: url.to_string(),
                    share_id: share_id.to_string(),
                    share_pwd: req.share_pwd.clone().unwrap_or_default(),
                },
            )
        }
        "virtual" => (
            "virtual",
            Credential::Virtual {
                num_file: req.num_file.unwrap_or(5),
                num_folder: req.num_folder.unwrap_or(0),
            },
        ),
        "bunny" => {
            let bucket = req
                .bucket
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((StatusCode::BAD_REQUEST, "Bunny 需要 bucket".to_string()))?;
            let access_key_id = req
                .access_key_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "Bunny 需要 access_key_id".to_string(),
                ))?;
            let secret_access_key = req
                .secret_access_key
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "Bunny 需要 secret_access_key".to_string(),
                ))?;
            (
                "bunny",
                Credential::Bunny {
                    bucket: bucket.to_string(),
                    endpoint: req.endpoint.clone().unwrap_or_default(),
                    region: req.region.clone().unwrap_or_else(|| "us-east-1".into()),
                    access_key_id: access_key_id.to_string(),
                    secret_access_key: secret_access_key.to_string(),
                    root_path: req.root_path.clone().unwrap_or_else(|| "/".into()),
                },
            )
        }
        "yandex_disk" => {
            let refresh_token = req
                .refresh_token
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "Yandex.Disk 需要 refresh_token".to_string(),
                ))?;
            (
                "yandex_disk",
                Credential::YandexDisk {
                    refresh_token: refresh_token.to_string(),
                    access_token: req.access_token.clone().unwrap_or_default(),
                    use_online_api: req.use_online_api.unwrap_or(true),
                    api_address: req.api_address.clone().unwrap_or_default(),
                    client_id: req.client_id.clone().unwrap_or_default(),
                    client_secret: req.client_secret.clone().unwrap_or_default(),
                    root_path: req.root_path.clone().unwrap_or_else(|| "/".into()),
                },
            )
        }
        "seafile" => {
            let address = req
                .address
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((StatusCode::BAD_REQUEST, "Seafile 需要 address".to_string()))?;
            (
                "seafile",
                Credential::Seafile {
                    address: address.to_string(),
                    username: req.username.clone().unwrap_or_default(),
                    password: req.password.clone().unwrap_or_default(),
                    token: req.token.clone().unwrap_or_default(),
                    repo_id: req.repo_id.clone().unwrap_or_default(),
                    repo_pwd: req.repo_pwd.clone().unwrap_or_default(),
                    root_path: req.root_path.clone().unwrap_or_else(|| "/".into()),
                },
            )
        }
        "kodbox" => {
            let address = req
                .address
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((StatusCode::BAD_REQUEST, "KodBox 需要 address".to_string()))?;
            (
                "kodbox",
                Credential::Kodbox {
                    address: address.to_string(),
                    username: req.username.clone().unwrap_or_default(),
                    password: req.password.clone().unwrap_or_default(),
                    root_path: req.root_path.clone().unwrap_or_default(),
                },
            )
        }
        "cloudreve_v4" => {
            let address = req
                .address
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "Cloudreve V4 需要 address".to_string(),
                ))?;
            (
                "cloudreve_v4",
                Credential::CloudreveV4 {
                    address: address.to_string(),
                    username: req.username.clone().unwrap_or_default(),
                    password: req.password.clone().unwrap_or_default(),
                    access_token: req.access_token.clone().unwrap_or_default(),
                    refresh_token: req.refresh_token.clone().unwrap_or_default(),
                    root_path: req.root_path.clone().unwrap_or_else(|| "/".into()),
                },
            )
        }
        "terabox" => {
            let cookie =
                cookie.ok_or((StatusCode::BAD_REQUEST, "Terabox 需要 cookie".to_string()))?;
            (
                "terabox",
                Credential::Terabox {
                    cookie,
                    download_api: req
                        .download_api
                        .clone()
                        .unwrap_or_else(|| "official".into()),
                    root_path: req.root_path.clone().unwrap_or_else(|| "/".into()),
                },
            )
        }
        "ilanzou" => {
            let username = req
                .username
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((StatusCode::BAD_REQUEST, "蓝奏云优创需要账号".to_string()))?;
            let password = req.password.clone().unwrap_or_default();
            (
                "ilanzou",
                Credential::Ilanzou {
                    site: req.site.clone().unwrap_or_else(|| "ilanzou".into()),
                    username: username.to_string(),
                    password,
                    root_folder_id: req.root_folder_id.clone().unwrap_or_else(|| "0".into()),
                },
            )
        }
        "halalcloud_open" => {
            let client_id = req
                .client_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "halalcloud 需要 client_id".to_string(),
                ))?
                .to_string();
            let client_secret = req
                .client_secret
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "halalcloud 需要 client_secret".to_string(),
                ))?
                .to_string();
            // meta.go 只要求 client_id / client_secret；个人 API 方式不需要令牌
            // （无令牌时按空 access_token 参与签名，与 Go 版 halalCommon.GetAccessToken 返回空串一致）
            let refresh_token = req
                .refresh_token
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            (
                "halalcloud_open",
                Credential::HalalcloudOpen {
                    client_id,
                    client_secret,
                    access_token: req.access_token.clone().unwrap_or_default(),
                    refresh_token: refresh_token.unwrap_or_default(),
                    host: req
                        .host
                        .clone()
                        .unwrap_or_else(|| "openapi.2dland.cn".to_string()),
                    timeout: req.timeout.unwrap_or(60),
                    root_path: req.root_path.clone().unwrap_or_else(|| "/".into()),
                },
            )
        }
        "netease_music" => {
            let cookie =
                cookie.ok_or((StatusCode::BAD_REQUEST, "网易云音乐需要 cookie".to_string()))?;
            (
                "netease_music",
                Credential::NeteaseMusic {
                    cookie,
                    song_limit: req.song_limit.unwrap_or(200),
                },
            )
        }
        other => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("不支持的网盘类型: {other}"),
            ))
        }
    };

    // 本机存储的根目录即挂载路径；其余驱动默认根 id 见 default_root_fid
    let root_fid = default_root_fid(driver_kind, &cred);

    let id = uuid::Uuid::new_v4().to_string();
    let driver = Driver::new(&id, &cred, st.store.clone())
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    let acc = Account {
        id: id.clone(),
        name: if req.name.trim().is_empty() {
            driver_display_name(driver_kind).to_string()
        } else {
            req.name.trim().to_string()
        },
        cred,
        root_fid,
        server_proxy: req.server_proxy,
        enabled: true,
    };
    {
        let mut data = st.store.data.lock().unwrap();
        data.accounts.push(acc.clone());
        st.store.save(&data).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("保存配置失败: {e}"),
            )
        })?;
    }
    st.drivers
        .lock()
        .unwrap()
        .insert(id.clone(), Arc::new(driver));

    Ok(Json(
        json!({ "id": id, "name": acc.name, "driver": driver_kind }),
    ))
}

/// GET /api/accounts/{id}/secret —— 返回该账号的凭据明细，仅用于编辑表单回填
///
/// 注意：此接口会返回 cookie / 密码 / refresh_token 等敏感信息，
/// 仅应由已登录的面板管理员在编辑账号时调用（受 /api/accounts 路由已有的鉴权保护）。
pub(crate) async fn get_account_secret(
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let data = st.store.data.lock().unwrap();
    let acc = data
        .accounts
        .iter()
        .find(|a| a.id == id)
        .ok_or((StatusCode::NOT_FOUND, "账号不存在".to_string()))?;

    let mut out = json!({
        "id": acc.id,
        "name": acc.name,
        "server_proxy": acc.server_proxy,
    });

    match &acc.cred {
        Credential::Quark { cookie } => {
            out["driver"] = json!("quark");
            out["cookie"] = json!(cookie);
        }
        Credential::QuarkUC { cookie } => {
            out["driver"] = json!("quark_uc");
            out["cookie"] = json!(cookie);
        }
        Credential::Pan123 {
            username, password, ..
        } => {
            out["driver"] = json!("123pan");
            out["username"] = json!(username);
            out["password"] = json!(password);
        }
        Credential::AliyundriveOpen {
            refresh_token,
            alipan_type,
            ..
        } => {
            out["driver"] = json!("aliyundrive_open");
            out["refresh_token"] = json!(refresh_token);
            out["alipan_type"] = json!(alipan_type);
        }
        Credential::BaiduNetdisk { refresh_token, .. } => {
            out["driver"] = json!("baidu_netdisk");
            out["refresh_token"] = json!(refresh_token);
        }
        Credential::Pan115 { cookie } => {
            out["driver"] = json!("pan115");
            out["cookie"] = json!(cookie);
        }
        Credential::Thunder {
            username, password, ..
        } => {
            out["driver"] = json!("thunder");
            out["username"] = json!(username);
            out["password"] = json!(password);
        }
        Credential::Lanzou {
            cookie,
            account,
            password,
        } => {
            out["driver"] = json!("lanzou");
            out["cookie"] = json!(cookie);
            out["username"] = json!(account);
            out["password"] = json!(password);
        }
        Credential::Yun139 {
            authorization,
            drive_type,
        } => {
            out["driver"] = json!("pan139");
            out["authorization"] = json!(authorization);
            out["drive_type"] = json!(drive_type);
        }
        Credential::Cloud189 {
            username, password, ..
        } => {
            out["driver"] = json!("cloud189");
            out["username"] = json!(username);
            out["password"] = json!(password);
        }
        Credential::Local { root_path } => {
            out["driver"] = json!("local");
            out["root_path"] = json!(root_path);
        }
        Credential::Webdav {
            url,
            username,
            password,
            root_path,
        } => {
            out["driver"] = json!("webdav");
            out["url"] = json!(url);
            out["username"] = json!(username);
            out["password"] = json!(password);
            out["root_path"] = json!(root_path);
        }
        Credential::Pan123Share {
            share_key,
            share_pwd,
            access_token,
        } => {
            out["driver"] = json!("123pan_share");
            out["share_key"] = json!(share_key);
            out["share_pwd"] = json!(share_pwd);
            out["access_token"] = json!(access_token);
        }
        Credential::Weiyun {
            cookies,
            root_folder_id,
        } => {
            out["driver"] = json!("weiyun");
            out["cookies"] = json!(cookies);
            out["root_folder_id"] = json!(root_folder_id);
        }
        Credential::Onedrive {
            region,
            is_sharepoint,
            site_id,
            root_path,
            refresh_token,
            ..
        } => {
            out["driver"] = json!("onedrive");
            out["region"] = json!(region);
            out["is_sharepoint"] = json!(is_sharepoint);
            out["site_id"] = json!(site_id);
            out["root_path"] = json!(root_path);
            out["refresh_token"] = json!(refresh_token);
        }
        Credential::GoogleDrive {
            refresh_token,
            root_folder_id,
            ..
        } => {
            out["driver"] = json!("google_drive");
            out["refresh_token"] = json!(refresh_token);
            out["root_folder_id"] = json!(root_folder_id);
        }
        Credential::S3 {
            bucket,
            endpoint,
            region,
            access_key_id,
            secret_access_key,
            session_token,
            custom_host,
            force_path_style,
            sign_url_expire,
            root_path,
        } => {
            out["driver"] = json!("s3");
            out["bucket"] = json!(bucket);
            out["endpoint"] = json!(endpoint);
            out["region"] = json!(region);
            out["access_key_id"] = json!(access_key_id);
            out["secret_access_key"] = json!(secret_access_key);
            out["session_token"] = json!(session_token);
            out["custom_host"] = json!(custom_host);
            out["force_path_style"] = json!(force_path_style);
            out["sign_url_expire"] = json!(sign_url_expire);
            out["root_path"] = json!(root_path);
        }
        Credential::Sftp {
            address,
            username,
            password,
            private_key,
            passphrase,
            root_path,
            ignore_symlink_error,
        } => {
            out["driver"] = json!("sftp");
            out["address"] = json!(address);
            out["username"] = json!(username);
            out["password"] = json!(password);
            out["private_key"] = json!(private_key);
            out["passphrase"] = json!(passphrase);
            out["root_path"] = json!(root_path);
            out["ignore_symlink_error"] = json!(ignore_symlink_error);
        }
        Credential::Ftp {
            address,
            username,
            password,
            encoding,
            root_path,
            cwd_list,
        } => {
            out["driver"] = json!("ftp");
            out["address"] = json!(address);
            out["username"] = json!(username);
            out["password"] = json!(password);
            out["encoding"] = json!(encoding);
            out["root_path"] = json!(root_path);
            out["cwd_list"] = json!(cwd_list);
        }
        Credential::Smb {
            address,
            username,
            password,
            share_name,
            root_path,
        } => {
            out["driver"] = json!("smb");
            out["address"] = json!(address);
            out["username"] = json!(username);
            out["password"] = json!(password);
            out["share_name"] = json!(share_name);
            out["root_path"] = json!(root_path);
        }
        Credential::AlistV3 {
            url,
            meta_password,
            username,
            password,
            token,
        } => {
            out["driver"] = json!("alist_v3");
            out["url"] = json!(url);
            out["meta_password"] = json!(meta_password);
            out["username"] = json!(username);
            out["password"] = json!(password);
            out["token"] = json!(token);
        }
        Credential::GithubReleases {
            repo_structure,
            token,
            show_all_version,
            show_source_code,
            gh_proxy,
            per_page,
            max_page,
        } => {
            out["driver"] = json!("github_releases");
            out["repo_structure"] = json!(repo_structure);
            out["token"] = json!(token);
            out["show_all_version"] = json!(show_all_version);
            out["show_source_code"] = json!(show_source_code);
            out["gh_proxy"] = json!(gh_proxy);
            out["per_page"] = json!(per_page);
            out["max_page"] = json!(max_page);
        }
        Credential::PikPak {
            username,
            password,
            refresh_token,
            access_token,
            device_id,
        } => {
            out["driver"] = json!("pikpak");
            out["username"] = json!(username);
            out["password"] = json!(password);
            out["refresh_token"] = json!(refresh_token);
            out["access_token"] = json!(access_token);
            out["device_id"] = json!(device_id);
        }
        Credential::OnedriveShare { url, password } => {
            out["driver"] = json!("onedrive_share");
            out["url"] = json!(url);
            out["password"] = json!(password);
        }
        Credential::Dropbox {
            refresh_token,
            access_token,
            root_path,
            use_online_api,
            client_id,
            client_secret,
        } => {
            out["driver"] = json!("dropbox");
            out["refresh_token"] = json!(refresh_token);
            out["access_token"] = json!(access_token);
            out["root_path"] = json!(root_path);
            out["use_online_api"] = json!(use_online_api);
            out["client_id"] = json!(client_id);
            out["client_secret"] = json!(client_secret);
        }
        Credential::GooglePhoto {
            refresh_token,
            access_token,
            client_id,
            client_secret,
        } => {
            out["driver"] = json!("google_photo");
            out["refresh_token"] = json!(refresh_token);
            out["access_token"] = json!(access_token);
            out["client_id"] = json!(client_id);
            out["client_secret"] = json!(client_secret);
        }
        Credential::Pan115Open {
            access_token,
            refresh_token,
        } => {
            out["driver"] = json!("pan115_open");
            out["access_token"] = json!(access_token);
            out["refresh_token"] = json!(refresh_token);
        }
        Credential::Pan115Share {
            cookie,
            share_code,
            receive_code,
        } => {
            out["driver"] = json!("pan115_share");
            out["cookie"] = json!(cookie);
            out["share_code"] = json!(share_code);
            out["receive_code"] = json!(receive_code);
        }
        Credential::Pan123Open {
            client_id,
            client_secret,
            refresh_token,
            access_token,
            use_online_api,
            api_address,
        } => {
            out["driver"] = json!("pan123_open");
            out["client_id"] = json!(client_id);
            out["client_secret"] = json!(client_secret);
            out["refresh_token"] = json!(refresh_token);
            out["access_token"] = json!(access_token);
            out["use_online_api"] = json!(use_online_api);
            out["api_address"] = json!(api_address);
        }
        Credential::Pan123Link {
            origin_urls,
            private_key,
            uid,
            valid_duration,
        } => {
            out["driver"] = json!("pan123_link");
            out["origin_urls"] = json!(origin_urls);
            out["private_key"] = json!(private_key);
            out["uid"] = json!(uid);
            out["valid_duration"] = json!(valid_duration);
        }
        Credential::Aliyundrive {
            refresh_token,
            access_token,
        } => {
            out["driver"] = json!("aliyundrive");
            out["refresh_token"] = json!(refresh_token);
            out["access_token"] = json!(access_token);
        }
        Credential::AliyundriveShare {
            refresh_token,
            access_token,
            share_id,
            share_pwd,
        } => {
            out["driver"] = json!("aliyundrive_share");
            out["refresh_token"] = json!(refresh_token);
            out["access_token"] = json!(access_token);
            out["share_id"] = json!(share_id);
            out["share_pwd"] = json!(share_pwd);
        }
        Credential::QuarkOpen {
            refresh_token,
            access_token,
            app_id,
            sign_key,
            use_online_api,
            api_address,
        } => {
            out["driver"] = json!("quark_open");
            out["refresh_token"] = json!(refresh_token);
            out["access_token"] = json!(access_token);
            out["app_id"] = json!(app_id);
            out["sign_key"] = json!(sign_key);
            out["use_online_api"] = json!(use_online_api);
            out["api_address"] = json!(api_address);
        }
        Credential::QuarkTv {
            refresh_token,
            access_token,
            device_id,
            link_method,
        } => {
            out["driver"] = json!("quark_tv");
            out["refresh_token"] = json!(refresh_token);
            out["access_token"] = json!(access_token);
            out["device_id"] = json!(device_id);
            out["link_method"] = json!(link_method);
        }
        Credential::UcTv {
            refresh_token,
            access_token,
            device_id,
            link_method,
        } => {
            out["driver"] = json!("uc_tv");
            out["refresh_token"] = json!(refresh_token);
            out["access_token"] = json!(access_token);
            out["device_id"] = json!(device_id);
            out["link_method"] = json!(link_method);
        }
        Credential::PikPakShare {
            share_id,
            share_pwd,
            platform,
            device_id,
            use_transcoding_address,
        } => {
            out["driver"] = json!("pikpak_share");
            out["share_id"] = json!(share_id);
            out["share_pwd"] = json!(share_pwd);
            out["platform"] = json!(platform);
            out["device_id"] = json!(device_id);
            out["use_transcoding_address"] = json!(use_transcoding_address);
        }
        Credential::OnedriveApp {
            region,
            client_id,
            client_secret,
            tenant_id,
            email,
            custom_host,
            root_path,
        } => {
            out["driver"] = json!("onedrive_app");
            out["region"] = json!(region);
            out["client_id"] = json!(client_id);
            out["client_secret"] = json!(client_secret);
            out["tenant_id"] = json!(tenant_id);
            out["email"] = json!(email);
            out["custom_host"] = json!(custom_host);
            out["root_path"] = json!(root_path);
        }
        Credential::Openlist {
            url,
            meta_password,
            username,
            password,
            token,
        } => {
            out["driver"] = json!("openlist");
            out["url"] = json!(url);
            out["meta_password"] = json!(meta_password);
            out["username"] = json!(username);
            out["password"] = json!(password);
            out["token"] = json!(token);
        }
        Credential::OpenlistShare {
            url,
            share_id,
            share_pwd,
        } => {
            out["driver"] = json!("openlist_share");
            out["url"] = json!(url);
            out["share_id"] = json!(share_id);
            out["share_pwd"] = json!(share_pwd);
        }
        Credential::Virtual {
            num_file,
            num_folder,
        } => {
            out["driver"] = json!("virtual");
            out["num_file"] = json!(num_file);
            out["num_folder"] = json!(num_folder);
        }
        Credential::Bunny {
            bucket,
            endpoint,
            region,
            access_key_id,
            secret_access_key,
            root_path,
        } => {
            out["driver"] = json!("bunny");
            out["bucket"] = json!(bucket);
            out["endpoint"] = json!(endpoint);
            out["region"] = json!(region);
            out["access_key_id"] = json!(access_key_id);
            out["secret_access_key"] = json!(secret_access_key);
            out["root_path"] = json!(root_path);
        }
        Credential::YandexDisk {
            refresh_token,
            access_token,
            use_online_api,
            api_address,
            client_id,
            client_secret,
            root_path,
        } => {
            out["driver"] = json!("yandex_disk");
            out["refresh_token"] = json!(refresh_token);
            out["access_token"] = json!(access_token);
            out["use_online_api"] = json!(use_online_api);
            out["api_address"] = json!(api_address);
            out["client_id"] = json!(client_id);
            out["client_secret"] = json!(client_secret);
            out["root_path"] = json!(root_path);
        }
        Credential::Seafile {
            address,
            username,
            password,
            token,
            repo_id,
            repo_pwd,
            root_path,
        } => {
            out["driver"] = json!("seafile");
            out["address"] = json!(address);
            out["username"] = json!(username);
            out["password"] = json!(password);
            out["token"] = json!(token);
            out["repo_id"] = json!(repo_id);
            out["repo_pwd"] = json!(repo_pwd);
            out["root_path"] = json!(root_path);
        }
        Credential::Kodbox {
            address,
            username,
            password,
            root_path,
        } => {
            out["driver"] = json!("kodbox");
            out["address"] = json!(address);
            out["username"] = json!(username);
            out["password"] = json!(password);
            out["root_path"] = json!(root_path);
        }
        Credential::CloudreveV4 {
            address,
            username,
            password,
            access_token,
            refresh_token,
            root_path,
        } => {
            out["driver"] = json!("cloudreve_v4");
            out["address"] = json!(address);
            out["username"] = json!(username);
            out["password"] = json!(password);
            out["access_token"] = json!(access_token);
            out["refresh_token"] = json!(refresh_token);
            out["root_path"] = json!(root_path);
        }
        Credential::Terabox {
            cookie,
            download_api,
            root_path,
        } => {
            out["driver"] = json!("terabox");
            out["cookie"] = json!(cookie);
            out["download_api"] = json!(download_api);
            out["root_path"] = json!(root_path);
        }
        Credential::Ilanzou {
            site,
            username,
            password,
            root_folder_id,
        } => {
            out["driver"] = json!("ilanzou");
            out["site"] = json!(site);
            out["username"] = json!(username);
            out["password"] = json!(password);
            out["root_folder_id"] = json!(root_folder_id);
        }
        Credential::HalalcloudOpen {
            client_id,
            client_secret,
            access_token,
            refresh_token,
            host,
            timeout,
            root_path,
        } => {
            out["driver"] = json!("halalcloud_open");
            out["client_id"] = json!(client_id);
            out["client_secret"] = json!(client_secret);
            out["access_token"] = json!(access_token);
            out["refresh_token"] = json!(refresh_token);
            out["host"] = json!(host);
            out["timeout"] = json!(timeout);
            out["root_path"] = json!(root_path);
        }
        Credential::NeteaseMusic { cookie, song_limit } => {
            out["driver"] = json!("netease_music");
            out["cookie"] = json!(cookie);
            out["song_limit"] = json!(song_limit);
        }
    }

    Ok(Json(out))
}

/// DELETE /api/accounts/{id}
pub(crate) async fn del_account(
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    {
        let mut data = st.store.data.lock().unwrap();
        let before = data.accounts.len();
        data.accounts.retain(|a| a.id != id);
        if data.accounts.len() == before {
            return Err((StatusCode::NOT_FOUND, "账号不存在".into()));
        }
        st.store.save(&data).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("保存配置失败: {e}"),
            )
        })?;
    }
    st.drivers.lock().unwrap().remove(&id);
    // 账号已删除，清空其全部目录缓存
    st.list_cache.invalidate_account(&id);
    Ok(Json(json!({ "ok": true })))
}

// ---------- 文件浏览 / 下载 ----------

#[derive(Deserialize)]
pub(crate) struct FilesQuery {
    pub(crate) account: String,
    #[serde(default)]
    pub(crate) fid: Option<String>,
    /// refresh=true 时跳过缓存，直接请求网盘并用结果覆盖缓存
    #[serde(default)]
    pub(crate) refresh: Option<bool>,
}

/// GET /api/files?account=&fid=&refresh=
///
/// 缓存策略（参考 OpenList）：
/// - 默认先查内存缓存（TTL 10 分钟），命中直接返回，不请求网盘
/// - refresh=true 跳过缓存，强制请求网盘并覆盖缓存（前端刷新按钮）
/// - 空结果不缓存，避免刚上传的文件在缓存期内不可见
pub(crate) async fn list_files(
    State(st): State<AppState>,
    Query(q): Query<FilesQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    // 禁用的账号不对外提供文件列表
    {
        let data = st.store.data.lock().unwrap();
        if let Some(acc) = data.accounts.iter().find(|a| a.id == q.account) {
            if !acc.enabled {
                return Err((StatusCode::FORBIDDEN, "该存储已禁用".into()));
            }
        }
    }
    let driver = st
        .get_driver(&q.account)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let fid = q.fid.unwrap_or_else(|| "0".into());
    let refresh = q.refresh.unwrap_or(false);
    let cache_key = format!("{}:{}", q.account, fid);

    // 命中缓存直接返回（refresh 请求跳过）
    if !refresh {
        if let Some(cached) = st.list_cache.get(&cache_key) {
            let mut entries = cached;
            sort_entries(&mut entries);
            return Ok(Json(json!({ "entries": entries })));
        }
    }

    let mut entries = driver
        .list(&fid)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    sort_entries(&mut entries);
    if !entries.is_empty() {
        st.list_cache.set(&cache_key, entries.clone());
    }
    Ok(Json(json!({ "entries": entries })))
}

pub(crate) fn sort_entries(entries: &mut [Entry]) {
    entries.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
}

#[derive(Deserialize)]
pub(crate) struct FileQuery {
    pub(crate) account: String,
    pub(crate) fid: String,
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) size: Option<u64>,
    #[serde(default)]
    pub(crate) etag: Option<String>,
    #[serde(default)]
    pub(crate) s3key: Option<String>,
    #[serde(default)]
    pub(crate) ftype: Option<i64>,
    #[serde(default)]
    pub(crate) isdir: Option<bool>,
    /// 驱动私有扩展信息（115 pick_code、百度 fs_id 等），原样透传
    /// query string 中为 JSON 字符串，需自定义反序列化
    #[serde(default, deserialize_with = "deserialize_json_str")]
    pub(crate) extra: Option<serde_json::Value>,
    /// inline=在线播放（Content-Disposition: inline），默认附件下载
    #[serde(default)]
    pub(crate) disp: Option<String>,
    /// proxy=1 强制走本服务中转（预览用：直链可能带 nosniff/octet-stream，浏览器播不了）
    #[serde(default)]
    pub(crate) proxy: Option<bool>,
}

impl FileQuery {
    fn to_entry(&self) -> Entry {
        Entry {
            fid: self.fid.clone(),
            name: self.name.clone().unwrap_or_default(),
            size: self.size.unwrap_or(0),
            is_dir: self.isdir.unwrap_or(false),
            updated_at: None,
            etag: self.etag.clone(),
            s3_key_flag: self.s3key.clone(),
            file_type: self.ftype,
            extra: self.extra.clone(),
        }
    }
}

/// GET /api/download —— 取直链（返回 url + 是否需代理）
///
/// 代理决策优先级：
/// 1. 账号开启了 server_proxy → 强制走本服务中转
/// 2. 驱动返回 proxy=true（如 115 网盘直链与 UA 绑定）→ 强制走本服务中转
/// 3. 其余情况 → 直链 302，客户端直接访问网盘服务器
pub(crate) async fn get_download(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<FileQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    // 取账号的 server_proxy 开关
    let account_server_proxy = {
        let data = st.store.data.lock().unwrap();
        data.accounts
            .iter()
            .find(|a| a.id == q.account)
            .map(|a| a.server_proxy)
            .unwrap_or(false)
    };

    let driver = st
        .get_driver(&q.account)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let info = driver
        .download(&q.to_entry())
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    // 需要代理的条件：账号开关 OR 驱动要求（如 115 UA 绑定直链）OR 客户端显式要求（预览）
    if account_server_proxy || info.proxy || q.proxy.unwrap_or(false) {
        // 将 url 重写为本服务的 /api/stream 端点，让客户端通过本服务中转
        let host = headers
            .get(header::HOST)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("127.0.0.1");
        let proto = headers
            .get("x-forwarded-proto")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("http");
        // 构造 /api/stream 查询参数，原样透传文件元信息（用 form_urlencoded 编码）
        let mut qs = url::form_urlencoded::Serializer::new(String::new());
        qs.append_pair("account", &q.account);
        qs.append_pair("fid", &q.fid);
        qs.append_pair("name", q.name.as_deref().unwrap_or(""));
        qs.append_pair("size", &q.size.unwrap_or(0).to_string());
        qs.append_pair("disp", "inline");
        if let Some(ref etag) = q.etag {
            qs.append_pair("etag", etag);
        }
        if let Some(ref s3k) = q.s3key {
            qs.append_pair("s3key", s3k);
        }
        if let Some(ft) = q.ftype {
            qs.append_pair("ftype", &ft.to_string());
        }
        if let Some(ref extra) = q.extra {
            qs.append_pair("extra", &extra.to_string());
        }
        let stream_url = format!("{proto}://{host}/api/stream?{}", qs.finish());
        Ok(Json(json!({
            "url": stream_url,
            "proxy": true,
        })))
    } else {
        Ok(Json(json!({
            "url": info.url,
            "proxy": false,
        })))
    }
}

/// 共享的流式代理：拉直链 -> 转发 Range -> 回写头 + Content-Disposition
/// 本机存储例外：local_path 非空时直接从磁盘流式读取，不走 reqwest
pub(crate) async fn proxy_stream(
    driver: &Arc<Driver>,
    e: &Entry,
    headers: &HeaderMap,
    disp: &str,
) -> Result<Response, (StatusCode, String)> {
    let info = driver
        .download(e)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("获取直链失败: {e}")))?;

    if let Some(path) = &info.local_path {
        return serve_local_file(path, e, headers, disp).await;
    }

    // FTP / SFTP / SMB：无 HTTP 直链，走协议 open_stream → 临时文件 → Range 响应
    {
        use crate::drivers::Driver as D;
        let proto_tmp = match driver.as_ref() {
            D::Ftp(d) => Some(d.open_stream(e).await),
            D::Sftp(d) => Some(d.open_stream(e).await),
            D::Smb(d) => Some(d.open_stream(e).await),
            _ => None,
        };
        if let Some(res) = proto_tmp {
            let (path, _len) = res.map_err(|e| (StatusCode::BAD_GATEWAY, e))?;
            let resp = serve_local_file(&path.to_string_lossy(), e, headers, disp).await;
            let _ = tokio::fs::remove_file(&path).await;
            return resp;
        }
    }

    // 115 等网盘的直链需要携带特定 User-Agent，且可能经过 HTTP 重定向。
    // reqwest 默认重定向时会剥离非标准 header（包括自定义 User-Agent），
    // 导致 115 服务器在跳转后返回 403 / 无效响应。
    // 解决方案：禁用自动重定向，手动跟随，每一跳都附带完整自定义头。
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_default();

    // 手动跟随重定向（最多 10 跳），每跳都带上 info.headers
    let range_val = headers
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let mut current_url = info.url.clone();
    let mut redirect_count = 0usize;
    let upstream = loop {
        if redirect_count > 10 {
            return Err((StatusCode::BAD_GATEWAY, "重定向次数超限".into()));
        }
        let mut req = client.get(&current_url);
        for (k, v) in &info.headers {
            req = req.header(k.as_str(), v.as_str());
        }
        if let Some(ref range) = range_val {
            req = req.header(header::RANGE, range.as_str());
        }
        let resp = req
            .send()
            .await
            .map_err(|e| (StatusCode::BAD_GATEWAY, format!("拉取直链失败: {e}")))?;
        let status = resp.status().as_u16();
        if status == 301 || status == 302 || status == 307 || status == 308 {
            let location = resp
                .headers()
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
                .ok_or_else(|| (StatusCode::BAD_GATEWAY, "重定向缺少 Location".to_string()))?;
            current_url = location;
            redirect_count += 1;
            continue;
        }
        break resp;
    };
    let status = upstream.status();
    let mut resp_builder =
        Response::builder().status(StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::OK));
    for h in [
        header::CONTENT_LENGTH,
        header::CONTENT_RANGE,
        header::ACCEPT_RANGES,
        header::ETAG,
        header::LAST_MODIFIED,
    ] {
        if let Some(v) = upstream.headers().get(&h) {
            resp_builder = resp_builder.header(&h, v);
        }
    }
    // Content-Type：上游常给 application/octet-stream（部分 CDN 还带
    // X-Content-Type-Options: nosniff），浏览器会因此拒绝当媒体播放/预览，
    // 这里按扩展名纠正（与本地存储同一套规则）
    let upstream_ctype = upstream
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let ctype =
        if upstream_ctype.is_empty() || upstream_ctype.starts_with("application/octet-stream") {
            content_type_by_ext(&e.name).to_string()
        } else {
            upstream_ctype.to_string()
        };
    resp_builder = resp_builder.header(header::CONTENT_TYPE, ctype);
    // Content-Disposition：inline 在线播放 / attachment 附件下载
    let fname = if e.name.is_empty() {
        "download"
    } else {
        &e.name
    };
    let encoded: String = fname
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    resp_builder = resp_builder.header(
        header::CONTENT_DISPOSITION,
        format!("{disp}; filename*=UTF-8''{encoded}"),
    );

    let stream = upstream.bytes_stream();
    let body = Body::from_stream(stream);
    resp_builder.body(body).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("构建响应失败: {e}"),
        )
    })
}

/// 本机存储流式读取：支持 Range 断点/拖动播放（对齐 proxy_stream 的响应头行为）
async fn serve_local_file(
    path: &str,
    e: &Entry,
    headers: &HeaderMap,
    disp: &str,
) -> Result<Response, (StatusCode, String)> {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};

    let file = tokio::fs::File::open(path).await.map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            (StatusCode::NOT_FOUND, "文件不存在".into())
        } else {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("打开文件失败: {err}"),
            )
        }
    })?;
    let total = file
        .metadata()
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("读取文件信息失败: {e}"),
            )
        })?
        .len();

    // 解析 Range: bytes=start-end / bytes=start- / bytes=-suffix（需结合 total 才能定后缀区间）
    let range = headers
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| parse_range(s, total));

    let (status, start, end, content_length) = match range {
        Some((start, end)) => (StatusCode::PARTIAL_CONTENT, start, end, end - start + 1),
        None => (StatusCode::OK, 0u64, total.saturating_sub(1), total),
    };

    let mut file = file;
    file.seek(std::io::SeekFrom::Start(start))
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("定位文件失败: {e}"),
            )
        })?;
    let stream = tokio_util::io::ReaderStream::with_capacity(file.take(content_length), 64 * 1024);

    let mut resp = Response::builder().status(status);
    if status == StatusCode::PARTIAL_CONTENT {
        resp = resp.header(
            header::CONTENT_RANGE,
            format!("bytes {start}-{end}/{total}"),
        );
    }
    resp = resp
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::CONTENT_LENGTH, content_length)
        .header(header::CONTENT_TYPE, content_type_by_ext(&e.name));

    // Content-Disposition：inline 在线播放 / attachment 附件下载
    let fname = if e.name.is_empty() {
        "download"
    } else {
        &e.name
    };
    let encoded: String = fname
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    resp = resp.header(
        header::CONTENT_DISPOSITION,
        format!("{disp}; filename*=UTF-8''{encoded}"),
    );

    resp.body(Body::from_stream(stream)).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("构建响应失败: {e}"),
        )
    })
}

/// 解析 "bytes=start-end" 形式的 Range 头（不含多区间），返回绝对的 (start, end) 闭区间
///
/// 需要 `total` 才能正确处理后缀区间 `bytes=-N`（最后 N 字节）——早期实现拿 `u64::MAX`
/// 当占位，调用方再 `min(total-1)`，结果 `bytes=-500` 只会返回最后 1 个字节，
/// Safari/iOS 播放视频时会直接报错。
fn parse_range(s: &str, total: u64) -> Option<(u64, u64)> {
    let rest = s.strip_prefix("bytes=")?;
    // 仅取第一个区间
    let first = rest.split(',').next()?.trim();
    let (start_s, end_s) = first.split_once('-')?;
    let (start_s, end_s) = (start_s.trim(), end_s.trim());
    let last = total.saturating_sub(1);
    match (start_s.parse::<u64>(), end_s.parse::<u64>()) {
        // bytes=start-end
        (Ok(start), Ok(end)) => {
            if start > end || start >= total {
                None
            } else {
                Some((start, end.min(last)))
            }
        }
        // bytes=start-
        (Ok(start), Err(_)) if end_s.is_empty() => {
            if start >= total {
                None
            } else {
                Some((start, last))
            }
        }
        // bytes=-suffix
        (Err(_), Ok(suffix)) if start_s.is_empty() && suffix > 0 => {
            if total == 0 {
                None
            } else {
                Some((total.saturating_sub(suffix), last))
            }
        }
        _ => None,
    }
}

/// 按扩展名粗略推断 Content-Type（在线播放场景）
pub(crate) fn content_type_by_ext(name: &str) -> &'static str {
    let ext = name.rsplit('.').next().unwrap_or("").to_lowercase();
    match ext.as_str() {
        "mp4" | "m4v" => "video/mp4",
        "mkv" => "video/x-matroska",
        "webm" => "video/webm",
        "avi" => "video/x-msvideo",
        "mov" => "video/quicktime",
        "flv" => "video/x-flv",
        "ts" => "video/mp2t",
        "mp3" => "audio/mpeg",
        "flac" => "audio/flac",
        "ogg" | "opus" => "audio/ogg",
        "m4a" => "audio/mp4",
        "wav" => "audio/wav",
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "pdf" => "application/pdf",
        "txt" | "md" | "log" | "srt" | "ass" | "vtt" => "text/plain; charset=utf-8",
        "html" | "htm" => "text/html; charset=utf-8",
        "json" => "application/json",
        _ => "application/octet-stream",
    }
}

/// GET /api/stream —— 面板用流式下载/播放
pub(crate) async fn stream_file(
    State(st): State<AppState>,
    Query(q): Query<FileQuery>,
    headers: HeaderMap,
) -> Result<Response, (StatusCode, String)> {
    let driver = st
        .get_driver(&q.account)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let disp = if q.disp.as_deref() == Some("inline") {
        "inline"
    } else {
        "attachment"
    };
    proxy_stream(&driver, &q.to_entry(), &headers, disp).await
}

/// PUT /api/accounts/{id} —— 编辑已有账号（替换凭据 + 名称 + server_proxy）
///
/// 流程：先删旧驱动缓存，用新凭据重新验证，验证成功后原地替换配置，保持 id 不变。
pub(crate) async fn edit_account(
    State(st): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<AddAccountReq>,
) -> Result<Json<Value>, (StatusCode, String)> {
    // 确认账号存在
    {
        let data = st.store.data.lock().unwrap();
        if !data.accounts.iter().any(|a| a.id == id) {
            return Err((StatusCode::NOT_FOUND, "账号不存在".into()));
        }
    }

    let cookie = req
        .cookie
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let userpass = match (
        req.username.as_deref().map(str::trim),
        req.password.as_deref().map(str::trim),
    ) {
        (Some(u), Some(p)) if !u.is_empty() && !p.is_empty() => {
            Some((u.to_string(), p.to_string()))
        }
        _ => None,
    };
    let refresh = req
        .refresh_token
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let kind = req
        .driver
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .ok_or((StatusCode::BAD_REQUEST, "缺少网盘类型".to_string()))?;

    let (driver_kind, cred) = match kind.as_str() {
        "quark" => (
            "quark",
            Credential::Quark {
                cookie: cookie.ok_or((StatusCode::BAD_REQUEST, "夸克需要 cookie".to_string()))?,
            },
        ),
        "quark_uc" | "uc" => (
            "quark_uc",
            Credential::QuarkUC {
                cookie: cookie
                    .ok_or((StatusCode::BAD_REQUEST, "UC 网盘需要 cookie".to_string()))?,
            },
        ),
        "123pan" => {
            let (u, p) =
                userpass.ok_or((StatusCode::BAD_REQUEST, "123 网盘需要账号密码".to_string()))?;
            (
                "123pan",
                Credential::Pan123 {
                    username: u,
                    password: p,
                    access_token: String::new(),
                    platform: "web".into(),
                },
            )
        }
        // 旧版 "aliyundrive" 走下方独立分支；开放平台仅匹配 open / aliyun 别名
        "aliyundrive_open" | "aliyun" => (
            "aliyundrive_open",
            Credential::AliyundriveOpen {
                refresh_token: refresh.ok_or((
                    StatusCode::BAD_REQUEST,
                    "阿里云盘需要 refresh_token".to_string(),
                ))?,
                access_token: String::new(),
                alipan_type: if req.alipan_type.as_deref() == Some("alipanTV") {
                    "alipanTV".into()
                } else {
                    "default".into()
                },
            },
        ),
        "baidu_netdisk" | "baidu" => (
            "baidu_netdisk",
            Credential::BaiduNetdisk {
                refresh_token: refresh.ok_or((
                    StatusCode::BAD_REQUEST,
                    "百度网盘需要 refresh_token".to_string(),
                ))?,
                access_token: String::new(),
            },
        ),
        "pan115" | "115" => (
            "pan115",
            Credential::Pan115 {
                cookie: cookie.ok_or((
                    StatusCode::BAD_REQUEST,
                    "115 网盘需要 cookie（含 UID/CID/SEID）".to_string(),
                ))?,
            },
        ),
        "thunder" | "xunlei" => {
            let (u, p) =
                userpass.ok_or((StatusCode::BAD_REQUEST, "迅雷网盘需要账号密码".to_string()))?;
            (
                "thunder",
                Credential::Thunder {
                    username: u,
                    password: p,
                    refresh_token: String::new(),
                    captcha_token: String::new(),
                    device_id: String::new(),
                },
            )
        }
        "lanzou" | "lanzouyun" => {
            let account = req.username.clone().unwrap_or_default().trim().to_string();
            let password = req.password.clone().unwrap_or_default();
            let cookie = req.cookie.clone().unwrap_or_default().trim().to_string();
            if account.is_empty() && cookie.is_empty() {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "蓝奏云需要账号密码或 cookie".to_string(),
                ));
            }
            (
                "lanzou",
                Credential::Lanzou {
                    cookie,
                    account,
                    password,
                },
            )
        }
        "pan139" | "139yun" | "mobile" => {
            let auth = req
                .authorization
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "移动云盘需要 139 Authorization".to_string(),
                ))?;
            (
                "pan139",
                Credential::Yun139 {
                    authorization: auth.to_string(),
                    drive_type: "personal_new".into(),
                },
            )
        }
        "cloud189" | "189" | "tianyi" => {
            let (u, p) =
                userpass.ok_or((StatusCode::BAD_REQUEST, "天翼云盘需要账号密码".to_string()))?;
            (
                "cloud189",
                Credential::Cloud189 {
                    username: u,
                    password: p,
                    cookie: String::new(),
                },
            )
        }
        "local" => {
            let root_path = req
                .root_path
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "本机存储需要挂载目录路径".to_string(),
                ))?;
            (
                "local",
                Credential::Local {
                    root_path: root_path.to_string(),
                },
            )
        }
        "webdav" => {
            let url = req
                .url
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((StatusCode::BAD_REQUEST, "WebDAV 需要服务器地址".to_string()))?;
            (
                "webdav",
                Credential::Webdav {
                    url: url.to_string(),
                    username: req.username.clone().unwrap_or_default(),
                    password: req.password.clone().unwrap_or_default(),
                    root_path: req
                        .root_path
                        .as_deref()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .unwrap_or("/")
                        .to_string(),
                },
            )
        }
        "123pan_share" | "123share" => {
            let share_key = req
                .share_key
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((StatusCode::BAD_REQUEST, "123 分享需要 shareKey".to_string()))?;
            (
                "123pan_share",
                Credential::Pan123Share {
                    share_key: share_key.to_string(),
                    share_pwd: req.share_pwd.clone().unwrap_or_default(),
                    access_token: req.access_token.clone().unwrap_or_default(),
                },
            )
        }
        "weiyun" => {
            let cookies = req
                .cookies
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "腾讯微云需要登录 cookie".to_string(),
                ))?;
            (
                "weiyun",
                Credential::Weiyun {
                    cookies: cookies.to_string(),
                    root_folder_id: String::new(),
                },
            )
        }
        "onedrive" => {
            let rt = refresh.ok_or((
                StatusCode::BAD_REQUEST,
                "OneDrive 需要 refresh_token".to_string(),
            ))?;
            (
                "onedrive",
                Credential::Onedrive {
                    region: req
                        .region
                        .as_deref()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .unwrap_or("global")
                        .to_string(),
                    is_sharepoint: req.is_sharepoint,
                    site_id: req.site_id.clone().unwrap_or_default(),
                    root_path: req
                        .root_path
                        .as_deref()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .unwrap_or("/")
                        .to_string(),
                    refresh_token: rt,
                    access_token: String::new(),
                },
            )
        }
        "google_drive" | "google" | "googledrive" => {
            let rt = refresh.ok_or((
                StatusCode::BAD_REQUEST,
                "Google Drive 需要 refresh_token".to_string(),
            ))?;
            (
                "google_drive",
                Credential::GoogleDrive {
                    refresh_token: rt,
                    access_token: String::new(),
                    root_folder_id: req.root_folder_id.clone().unwrap_or_default(),
                },
            )
        }

        "s3" => {
            let bucket = req
                .bucket
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((StatusCode::BAD_REQUEST, "S3 需要 bucket".to_string()))?;
            let endpoint = req
                .endpoint
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((StatusCode::BAD_REQUEST, "S3 需要 endpoint".to_string()))?;
            let access_key_id = req
                .access_key_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((StatusCode::BAD_REQUEST, "S3 需要 access_key_id".to_string()))?;
            let secret_access_key = req
                .secret_access_key
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "S3 需要 secret_access_key".to_string(),
                ))?;
            (
                "s3",
                Credential::S3 {
                    bucket: bucket.to_string(),
                    endpoint: endpoint.to_string(),
                    region: req.region.clone().unwrap_or_else(|| "us-east-1".into()),
                    access_key_id: access_key_id.to_string(),
                    secret_access_key: secret_access_key.to_string(),
                    session_token: req.session_token.clone().unwrap_or_default(),
                    custom_host: req.custom_host.clone().unwrap_or_default(),
                    force_path_style: req.force_path_style.unwrap_or(false),
                    sign_url_expire: req.sign_url_expire.unwrap_or(4),
                    root_path: req.root_path.clone().unwrap_or_else(|| "/".into()),
                },
            )
        }
        "sftp" => {
            let address = req
                .address
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((StatusCode::BAD_REQUEST, "SFTP 需要 address".to_string()))?;
            let username = req
                .username
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((StatusCode::BAD_REQUEST, "SFTP 需要 username".to_string()))?;
            (
                "sftp",
                Credential::Sftp {
                    address: address.to_string(),
                    username: username.to_string(),
                    password: req.password.clone().unwrap_or_default(),
                    private_key: req.private_key.clone().unwrap_or_default(),
                    passphrase: req.passphrase.clone().unwrap_or_default(),
                    root_path: req.root_path.clone().unwrap_or_else(|| "/".into()),
                    ignore_symlink_error: req.ignore_symlink_error.unwrap_or(false),
                },
            )
        }
        "ftp" => {
            let address = req
                .address
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((StatusCode::BAD_REQUEST, "FTP 需要 address".to_string()))?;
            let username = req
                .username
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((StatusCode::BAD_REQUEST, "FTP 需要 username".to_string()))?;
            let password = req.password.clone().unwrap_or_default();
            (
                "ftp",
                Credential::Ftp {
                    address: address.to_string(),
                    username: username.to_string(),
                    password,
                    encoding: req.encoding.clone().unwrap_or_default(),
                    root_path: req.root_path.clone().unwrap_or_else(|| "/".into()),
                    cwd_list: req.cwd_list.unwrap_or(false),
                },
            )
        }
        "smb" => {
            let address = req
                .address
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((StatusCode::BAD_REQUEST, "SMB 需要 address".to_string()))?;
            let username = req
                .username
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((StatusCode::BAD_REQUEST, "SMB 需要 username".to_string()))?;
            let share_name = req
                .share_name
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((StatusCode::BAD_REQUEST, "SMB 需要 share_name".to_string()))?;
            (
                "smb",
                Credential::Smb {
                    address: address.to_string(),
                    username: username.to_string(),
                    password: req.password.clone().unwrap_or_default(),
                    share_name: share_name.to_string(),
                    root_path: req.root_path.clone().unwrap_or_default(),
                },
            )
        }
        "alist_v3" => {
            let url = req
                .url
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((StatusCode::BAD_REQUEST, "AList V3 需要 url".to_string()))?;
            (
                "alist_v3",
                Credential::AlistV3 {
                    url: url.to_string(),
                    meta_password: req.meta_password.clone().unwrap_or_default(),
                    username: req.username.clone().unwrap_or_default(),
                    password: req.password.clone().unwrap_or_default(),
                    token: req.token.clone().unwrap_or_default(),
                },
            )
        }
        "github_releases" => {
            let repo_structure = req
                .repo_structure
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "GitHub Releases 需要 repo_structure".to_string(),
                ))?;
            (
                "github_releases",
                Credential::GithubReleases {
                    repo_structure: repo_structure.to_string(),
                    token: req.token.clone().unwrap_or_default(),
                    show_all_version: req.show_all_version.unwrap_or(false),
                    show_source_code: req.show_source_code.unwrap_or(false),
                    gh_proxy: req.gh_proxy.clone().unwrap_or_default(),
                    per_page: req.per_page.unwrap_or(30),
                    max_page: req.max_page.unwrap_or(0),
                },
            )
        }
        "pikpak" => {
            let username = req
                .username
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((StatusCode::BAD_REQUEST, "PikPak 需要 username".to_string()))?;
            let password = req.password.clone().unwrap_or_default();
            (
                "pikpak",
                Credential::PikPak {
                    username: username.to_string(),
                    password,
                    refresh_token: req.refresh_token.clone().unwrap_or_default(),
                    access_token: req.access_token.clone().unwrap_or_default(),
                    device_id: req.device_id.clone().unwrap_or_default(),
                },
            )
        }
        "onedrive_share" => {
            let url = req
                .url
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((StatusCode::BAD_REQUEST, "OneDrive 分享需要 url".to_string()))?;
            (
                "onedrive_share",
                Credential::OnedriveShare {
                    url: url.to_string(),
                    password: req.password.clone().unwrap_or_default(),
                },
            )
        }
        "dropbox" => {
            let refresh_token = req
                .refresh_token
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "Dropbox 需要 refresh_token".to_string(),
                ))?;
            (
                "dropbox",
                Credential::Dropbox {
                    refresh_token: refresh_token.to_string(),
                    access_token: req.access_token.clone().unwrap_or_default(),
                    root_path: req.root_path.clone().unwrap_or_default(),
                    use_online_api: req.use_online_api.unwrap_or(true),
                    client_id: req.client_id.clone().unwrap_or_default(),
                    client_secret: req.client_secret.clone().unwrap_or_default(),
                },
            )
        }
        "google_photo" => {
            let refresh_token = req
                .refresh_token
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "Google Photos 需要 refresh_token".to_string(),
                ))?;
            (
                "google_photo",
                Credential::GooglePhoto {
                    refresh_token: refresh_token.to_string(),
                    access_token: req.access_token.clone().unwrap_or_default(),
                    client_id: req.client_id.clone().unwrap_or_default(),
                    client_secret: req.client_secret.clone().unwrap_or_default(),
                },
            )
        }
        "pan115_open" | "115_open" => {
            let access_token = req.access_token.clone().unwrap_or_default();
            let refresh_token = req.refresh_token.clone().unwrap_or_default();
            if access_token.is_empty() && refresh_token.is_empty() {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "115 Open 需要 access_token 或 refresh_token".into(),
                ));
            }
            (
                "pan115_open",
                Credential::Pan115Open {
                    access_token,
                    refresh_token,
                },
            )
        }
        "pan115_share" | "115_share" => {
            let share_code = req
                .share_code
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "115 分享需要 share_code".to_string(),
                ))?;
            (
                "pan115_share",
                Credential::Pan115Share {
                    cookie: req.cookie.clone().unwrap_or_default(),
                    share_code: share_code.to_string(),
                    receive_code: req.receive_code.clone().unwrap_or_default(),
                },
            )
        }
        "pan123_open" | "123_open" => (
            "pan123_open",
            Credential::Pan123Open {
                client_id: req.client_id.clone().unwrap_or_default(),
                client_secret: req.client_secret.clone().unwrap_or_default(),
                refresh_token: req.refresh_token.clone().unwrap_or_default(),
                access_token: req.access_token.clone().unwrap_or_default(),
                use_online_api: req.use_online_api.unwrap_or(true),
                api_address: req.api_address.clone().unwrap_or_default(),
            },
        ),
        "pan123_link" | "123_link" => {
            let origin_urls = req
                .origin_urls
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "123PanLink 需要 origin_urls".to_string(),
                ))?;
            (
                "pan123_link",
                Credential::Pan123Link {
                    origin_urls: origin_urls.to_string(),
                    private_key: req.private_key.clone().unwrap_or_default(),
                    uid: req.uid.unwrap_or(0),
                    valid_duration: req.valid_duration.unwrap_or(30),
                },
            )
        }
        "aliyundrive" => {
            let refresh_token = req
                .refresh_token
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "阿里云盘(旧)需要 refresh_token".to_string(),
                ))?;
            (
                "aliyundrive",
                Credential::Aliyundrive {
                    refresh_token: refresh_token.to_string(),
                    access_token: req.access_token.clone().unwrap_or_default(),
                },
            )
        }
        "aliyundrive_share" => {
            let refresh_token = req
                .refresh_token
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "阿里分享需要 refresh_token".to_string(),
                ))?;
            let share_id = req
                .share_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((StatusCode::BAD_REQUEST, "阿里分享需要 share_id".to_string()))?;
            (
                "aliyundrive_share",
                Credential::AliyundriveShare {
                    refresh_token: refresh_token.to_string(),
                    access_token: req.access_token.clone().unwrap_or_default(),
                    share_id: share_id.to_string(),
                    share_pwd: req.share_pwd.clone().unwrap_or_default(),
                },
            )
        }
        "quark_open" => {
            let refresh_token = req
                .refresh_token
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "夸克 Open 需要 refresh_token".to_string(),
                ))?;
            let app_id = req
                .app_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((StatusCode::BAD_REQUEST, "夸克 Open 需要 app_id".to_string()))?;
            let sign_key = req
                .sign_key
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "夸克 Open 需要 sign_key".to_string(),
                ))?;
            (
                "quark_open",
                Credential::QuarkOpen {
                    refresh_token: refresh_token.to_string(),
                    access_token: req.access_token.clone().unwrap_or_default(),
                    app_id: app_id.to_string(),
                    sign_key: sign_key.to_string(),
                    use_online_api: req.use_online_api.unwrap_or(true),
                    api_address: req.api_address.clone().unwrap_or_default(),
                },
            )
        }
        "quark_tv" => (
            "quark_tv",
            Credential::QuarkTv {
                refresh_token: req.refresh_token.clone().unwrap_or_default(),
                access_token: req.access_token.clone().unwrap_or_default(),
                device_id: req.device_id.clone().unwrap_or_default(),
                link_method: req.link_method.clone().unwrap_or_else(|| "download".into()),
            },
        ),
        "uc_tv" => (
            "uc_tv",
            Credential::UcTv {
                refresh_token: req.refresh_token.clone().unwrap_or_default(),
                access_token: req.access_token.clone().unwrap_or_default(),
                device_id: req.device_id.clone().unwrap_or_default(),
                link_method: req.link_method.clone().unwrap_or_else(|| "download".into()),
            },
        ),

        "pikpak_share" => {
            let share_id = req
                .share_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "PikPak 分享需要 share_id".to_string(),
                ))?;
            (
                "pikpak_share",
                Credential::PikPakShare {
                    share_id: share_id.to_string(),
                    share_pwd: req.share_pwd.clone().unwrap_or_default(),
                    platform: req.platform.clone().unwrap_or_else(|| "web".into()),
                    device_id: req.device_id.clone().unwrap_or_default(),
                    use_transcoding_address: req.use_transcoding_address.unwrap_or(false),
                },
            )
        }
        "onedrive_app" => {
            let client_id = req
                .client_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "OneDrive APP 需要 client_id".to_string(),
                ))?;
            let client_secret = req
                .client_secret
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "OneDrive APP 需要 client_secret".to_string(),
                ))?;
            let email = req
                .email
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "OneDrive APP 需要用户邮箱 email".to_string(),
                ))?;
            (
                "onedrive_app",
                Credential::OnedriveApp {
                    region: req.region.clone().unwrap_or_else(|| "global".into()),
                    client_id: client_id.to_string(),
                    client_secret: client_secret.to_string(),
                    tenant_id: req.tenant_id.clone().unwrap_or_default(),
                    email: email.to_string(),
                    custom_host: req.custom_host.clone().unwrap_or_default(),
                    root_path: req.root_path.clone().unwrap_or_else(|| "/".into()),
                },
            )
        }
        "openlist" => {
            let url = req
                .url
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((StatusCode::BAD_REQUEST, "OpenList 需要 url".to_string()))?;
            (
                "openlist",
                Credential::Openlist {
                    url: url.to_string(),
                    meta_password: req.meta_password.clone().unwrap_or_default(),
                    username: req.username.clone().unwrap_or_default(),
                    password: req.password.clone().unwrap_or_default(),
                    token: req.token.clone().unwrap_or_default(),
                },
            )
        }
        "openlist_share" => {
            let url = req
                .url
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((StatusCode::BAD_REQUEST, "OpenList 分享需要 url".to_string()))?;
            let share_id = req
                .share_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "OpenList 分享需要 share_id".to_string(),
                ))?;
            (
                "openlist_share",
                Credential::OpenlistShare {
                    url: url.to_string(),
                    share_id: share_id.to_string(),
                    share_pwd: req.share_pwd.clone().unwrap_or_default(),
                },
            )
        }
        "virtual" => (
            "virtual",
            Credential::Virtual {
                num_file: req.num_file.unwrap_or(5),
                num_folder: req.num_folder.unwrap_or(0),
            },
        ),
        "bunny" => {
            let bucket = req
                .bucket
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((StatusCode::BAD_REQUEST, "Bunny 需要 bucket".to_string()))?;
            let access_key_id = req
                .access_key_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "Bunny 需要 access_key_id".to_string(),
                ))?;
            let secret_access_key = req
                .secret_access_key
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "Bunny 需要 secret_access_key".to_string(),
                ))?;
            (
                "bunny",
                Credential::Bunny {
                    bucket: bucket.to_string(),
                    endpoint: req.endpoint.clone().unwrap_or_default(),
                    region: req.region.clone().unwrap_or_else(|| "us-east-1".into()),
                    access_key_id: access_key_id.to_string(),
                    secret_access_key: secret_access_key.to_string(),
                    root_path: req.root_path.clone().unwrap_or_else(|| "/".into()),
                },
            )
        }
        "yandex_disk" => {
            let refresh_token = req
                .refresh_token
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "Yandex.Disk 需要 refresh_token".to_string(),
                ))?;
            (
                "yandex_disk",
                Credential::YandexDisk {
                    refresh_token: refresh_token.to_string(),
                    access_token: req.access_token.clone().unwrap_or_default(),
                    use_online_api: req.use_online_api.unwrap_or(true),
                    api_address: req.api_address.clone().unwrap_or_default(),
                    client_id: req.client_id.clone().unwrap_or_default(),
                    client_secret: req.client_secret.clone().unwrap_or_default(),
                    root_path: req.root_path.clone().unwrap_or_else(|| "/".into()),
                },
            )
        }
        "seafile" => {
            let address = req
                .address
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((StatusCode::BAD_REQUEST, "Seafile 需要 address".to_string()))?;
            (
                "seafile",
                Credential::Seafile {
                    address: address.to_string(),
                    username: req.username.clone().unwrap_or_default(),
                    password: req.password.clone().unwrap_or_default(),
                    token: req.token.clone().unwrap_or_default(),
                    repo_id: req.repo_id.clone().unwrap_or_default(),
                    repo_pwd: req.repo_pwd.clone().unwrap_or_default(),
                    root_path: req.root_path.clone().unwrap_or_else(|| "/".into()),
                },
            )
        }
        "kodbox" => {
            let address = req
                .address
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((StatusCode::BAD_REQUEST, "KodBox 需要 address".to_string()))?;
            (
                "kodbox",
                Credential::Kodbox {
                    address: address.to_string(),
                    username: req.username.clone().unwrap_or_default(),
                    password: req.password.clone().unwrap_or_default(),
                    root_path: req.root_path.clone().unwrap_or_default(),
                },
            )
        }
        "cloudreve_v4" => {
            let address = req
                .address
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "Cloudreve V4 需要 address".to_string(),
                ))?;
            (
                "cloudreve_v4",
                Credential::CloudreveV4 {
                    address: address.to_string(),
                    username: req.username.clone().unwrap_or_default(),
                    password: req.password.clone().unwrap_or_default(),
                    access_token: req.access_token.clone().unwrap_or_default(),
                    refresh_token: req.refresh_token.clone().unwrap_or_default(),
                    root_path: req.root_path.clone().unwrap_or_else(|| "/".into()),
                },
            )
        }
        "terabox" => {
            let cookie =
                cookie.ok_or((StatusCode::BAD_REQUEST, "Terabox 需要 cookie".to_string()))?;
            (
                "terabox",
                Credential::Terabox {
                    cookie,
                    download_api: req
                        .download_api
                        .clone()
                        .unwrap_or_else(|| "official".into()),
                    root_path: req.root_path.clone().unwrap_or_else(|| "/".into()),
                },
            )
        }
        "ilanzou" => {
            let username = req
                .username
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((StatusCode::BAD_REQUEST, "蓝奏云优创需要账号".to_string()))?;
            let password = req.password.clone().unwrap_or_default();
            (
                "ilanzou",
                Credential::Ilanzou {
                    site: req.site.clone().unwrap_or_else(|| "ilanzou".into()),
                    username: username.to_string(),
                    password,
                    root_folder_id: req.root_folder_id.clone().unwrap_or_else(|| "0".into()),
                },
            )
        }
        "halalcloud_open" => {
            let client_id = req
                .client_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "halalcloud 需要 client_id".to_string(),
                ))?
                .to_string();
            let client_secret = req
                .client_secret
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((
                    StatusCode::BAD_REQUEST,
                    "halalcloud 需要 client_secret".to_string(),
                ))?
                .to_string();
            // meta.go 只要求 client_id / client_secret；个人 API 方式不需要令牌
            // （无令牌时按空 access_token 参与签名，与 Go 版 halalCommon.GetAccessToken 返回空串一致）
            let refresh_token = req
                .refresh_token
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            (
                "halalcloud_open",
                Credential::HalalcloudOpen {
                    client_id,
                    client_secret,
                    access_token: req.access_token.clone().unwrap_or_default(),
                    refresh_token: refresh_token.unwrap_or_default(),
                    host: req
                        .host
                        .clone()
                        .unwrap_or_else(|| "openapi.2dland.cn".to_string()),
                    timeout: req.timeout.unwrap_or(60),
                    root_path: req.root_path.clone().unwrap_or_else(|| "/".into()),
                },
            )
        }
        "netease_music" => {
            let cookie =
                cookie.ok_or((StatusCode::BAD_REQUEST, "网易云音乐需要 cookie".to_string()))?;
            (
                "netease_music",
                Credential::NeteaseMusic {
                    cookie,
                    song_limit: req.song_limit.unwrap_or(200),
                },
            )
        }
        other => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("不支持的网盘类型: {other}"),
            ))
        }
    };

    // 用新凭据验证（复用 Driver::new，失败则拒绝保存）
    let new_driver = Driver::new(&id, &cred, st.store.clone())
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    let new_name = if req.name.trim().is_empty() {
        driver_display_name(driver_kind).to_string()
    } else {
        req.name.trim().to_string()
    };

    // 原地替换配置，id 保持不变
    {
        let mut data = st.store.data.lock().unwrap();
        if let Some(acc) = data.accounts.iter_mut().find(|a| a.id == id) {
            acc.name = new_name.clone();
            // 根目录 fid 随驱动同步更新（本机存储 = 挂载路径，其余 = 驱动默认根 id）
            acc.root_fid = default_root_fid(driver_kind, &cred);
            acc.cred = cred;
            acc.server_proxy = req.server_proxy;
        }
        st.store.save(&data).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("保存配置失败: {e}"),
            )
        })?;
    }

    // 替换驱动缓存
    st.drivers
        .lock()
        .unwrap()
        .insert(id.clone(), Arc::new(new_driver));
    // 凭据已变更，清空该账号全部目录缓存，避免展示旧数据
    st.list_cache.invalidate_account(&id);

    Ok(Json(
        json!({ "id": id, "name": new_name, "driver": driver_kind }),
    ))
}

#[derive(Deserialize)]
pub(crate) struct PatchEnabledReq {
    enabled: bool,
}

/// PATCH /api/accounts/{id}/enabled —— 切换存储启用/禁用状态（不重验证凭据）
pub(crate) async fn patch_account_enabled(
    State(st): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<PatchEnabledReq>,
) -> Result<Json<Value>, (StatusCode, String)> {
    {
        let mut data = st.store.data.lock().unwrap();
        let acc = data
            .accounts
            .iter_mut()
            .find(|a| a.id == id)
            .ok_or((StatusCode::NOT_FOUND, "账号不存在".to_string()))?;
        acc.enabled = req.enabled;
        st.store.save(&data).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("保存配置失败: {e}"),
            )
        })?;
    }
    Ok(Json(json!({ "id": id, "enabled": req.enabled })))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn any_cred() -> Credential {
        Credential::Local {
            root_path: "/mnt/data".into(),
        }
    }

    /// 对照 Go 版各驱动 meta.go 的 DefaultRoot 字段
    #[test]
    fn test_default_root_fid_matches_go_meta() {
        let c = any_cred();
        let cases: &[(&str, &str)] = &[
            ("pan139", "/"),
            ("cloud189", "-11"),
            ("webdav", "/"),
            ("s3", "/"),
            ("sftp", "/"),
            ("ftp", "/"),
            ("alist_v3", "/"),
            ("github_releases", "/"),
            ("onedrive_app", "/"),
            ("pikpak_share", "/"),
            ("openlist", "/"),
            ("openlist_share", "/"),
            ("virtual", "/"),
            ("bunny", "/"),
            ("yandex_disk", "/"),
            ("seafile", "/"),
            ("kodbox", "/"),
            ("cloudreve_v4", "/"),
            ("terabox", "/"),
            ("smb", "."),
            ("123pan_share", "0"),
            ("weiyun", ""),
            ("aliyundrive_open", "root"),
            ("baidu_netdisk", "/"),
            ("lanzou", "-1"),
            ("halalcloud_open", "/"),
            ("netease_music", "/"),
        ];
        for (kind, want) in cases {
            assert_eq!(default_root_fid(kind, &c), *want, "driver={kind}");
        }
        // 未知驱动兜底 "0"
        assert_eq!(default_root_fid("some_unknown", &c), "0");
    }

    /// 四个驱动的默认根取自凭据字段，空串走各自兜底值
    #[test]
    fn test_default_root_fid_from_credential() {
        assert_eq!(
            default_root_fid(
                "local",
                &Credential::Local {
                    root_path: "/mnt/data".into()
                }
            ),
            "/mnt/data"
        );
        let ilanzou = |root_folder_id: &str| Credential::Ilanzou {
            site: "ilanzou".into(),
            username: "u".into(),
            password: "p".into(),
            root_folder_id: root_folder_id.into(),
        };
        assert_eq!(default_root_fid("ilanzou", &ilanzou("")), "0");
        assert_eq!(default_root_fid("ilanzou", &ilanzou("-1")), "-1");
        let onedrive = |root_path: &str| Credential::Onedrive {
            region: "global".into(),
            is_sharepoint: false,
            site_id: String::new(),
            root_path: root_path.into(),
            refresh_token: "rt".into(),
            access_token: String::new(),
        };
        assert_eq!(default_root_fid("onedrive", &onedrive("")), "/");
        assert_eq!(default_root_fid("onedrive", &onedrive("/docs")), "/docs");
        let gdrive = |root_folder_id: &str| Credential::GoogleDrive {
            refresh_token: "rt".into(),
            access_token: String::new(),
            root_folder_id: root_folder_id.into(),
        };
        assert_eq!(default_root_fid("google_drive", &gdrive("")), "root");
        assert_eq!(default_root_fid("google_drive", &gdrive("fid1")), "fid1");
    }

    /// 与 Go 版的分歧，仅钉住现状：Go 版 thunder 无 DefaultRoot，根用空串；
    /// Rust 版落在 `_ => "0"`。没有可用账号无法实测，改动前先拿账号验证。
    #[test]
    fn test_default_root_fid_thunder_unverified() {
        assert_eq!(default_root_fid("thunder", &any_cred()), "0");
    }

    #[test]
    fn test_parse_range_with_total() {
        // 显式闭区间
        assert_eq!(parse_range("bytes=0-99", 1000), Some((0, 99)));
        assert_eq!(parse_range("bytes=0-0", 1000), Some((0, 0)));
        // 开区间到结尾
        assert_eq!(parse_range("bytes=100-", 1000), Some((100, 999)));
        assert_eq!(parse_range("bytes=999-", 1000), Some((999, 999)));
        // 后缀区间：最后 N 字节（回归用例：曾只返回最后 1 字节）
        assert_eq!(parse_range("bytes=-500", 1000), Some((500, 999)));
        assert_eq!(parse_range("bytes=-1", 1000), Some((999, 999)));
        assert_eq!(parse_range("bytes=-1000", 1000), Some((0, 999)));
        assert_eq!(parse_range("bytes=-5000", 1000), Some((0, 999)));
        // 超出文件尾 -> 截到结尾
        assert_eq!(parse_range("bytes=0-99999", 1000), Some((0, 999)));
        // 起点越过文件尾 -> 不返回区间（整体 200）
        assert_eq!(parse_range("bytes=1000-", 1000), None);
        assert_eq!(parse_range("bytes=1000-2000", 1000), None);
        // 多区间只取第一段
        assert_eq!(parse_range("bytes=0-1,5-9", 1000), Some((0, 1)));
        // 非法头部
        assert_eq!(parse_range("bytes=-", 1000), None);
        assert_eq!(parse_range("bytes=abc", 1000), None);
        assert_eq!(parse_range("bytes=5-2", 1000), None);
        assert_eq!(parse_range("items=0-1", 1000), None);
        // 空文件
        assert_eq!(parse_range("bytes=0-", 0), None);
        assert_eq!(parse_range("bytes=-10", 0), None);
    }
}
