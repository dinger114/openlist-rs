use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

// ---------- 数据模型 ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "driver", rename_all = "snake_case")]
pub enum Credential {
    Quark {
        cookie: String,
    },
    Pan123 {
        username: String,
        password: String,
        #[serde(default)]
        access_token: String,
        #[serde(default = "default_platform")]
        platform: String,
    },
    /// 阿里云盘开放平台（refresh_token 授权）
    AliyundriveOpen {
        refresh_token: String,
        #[serde(default)]
        access_token: String,
        #[serde(default = "default_alipan_type")]
        alipan_type: String,
    },
    /// 百度网盘（refresh_token 授权，可用 olist 在线 API 刷新）
    BaiduNetdisk {
        refresh_token: String,
        #[serde(default)]
        access_token: String,
    },
    /// 115 网盘（cookie：UID/CID/SEID）
    Pan115 {
        cookie: String,
    },
    /// 迅雷网盘（账号密码登录）
    Thunder {
        username: String,
        password: String,
        #[serde(default)]
        refresh_token: String,
        #[serde(default)]
        captcha_token: String,
        #[serde(default)]
        device_id: String,
    },
    /// 蓝奏云（account 模式：账号密码自动登录并续期；cookie 模式：仅填 cookie）
    Lanzou {
        #[serde(default)]
        cookie: String,
        #[serde(default)]
        account: String,
        #[serde(default)]
        password: String,
    },
    /// 中国移动云盘（139，Authorization 授权，即 OpenList 139Yun 的 authorization 字段：
    /// base64("Basic xxx:手机号:token|...")，过期后自动刷新）
    Yun139 {
        authorization: String,
        /// personal_new（新版个人云，默认）或 personal（旧版个人云）
        #[serde(default = "default_yun139_type")]
        drive_type: String,
    },
    /// 天翼云盘（189，账号密码登录）
    Cloud189 {
        username: String,
        password: String,
        /// 需要验证码时可手工填充登录后的 cookie（目前实现未使用，保留字段）
        #[serde(default)]
        cookie: String,
    },
    /// UC 网盘（与夸克同源接口，域名不同）
    QuarkUC {
        cookie: String,
    },
    /// 本机存储（root_path 为挂载的本地目录）
    Local {
        root_path: String,
    },
    /// WebDAV（客户端模式，挂载其他 WebDAV 服务器）
    Webdav {
        url: String,
        #[serde(default)]
        username: String,
        #[serde(default)]
        password: String,
        #[serde(default = "default_webdav_root")]
        root_path: String,
    },
    /// 123 云盘分享（shareKey + 分享密码，只读）
    Pan123Share {
        share_key: String,
        #[serde(default)]
        share_pwd: String,
        #[serde(default)]
        access_token: String,
    },
    /// 腾讯微云（www.weiyun.com 登录后的 cookie）
    Weiyun {
        cookies: String,
        /// 根目录 dir_key，留空则自动取账号主目录
        #[serde(default)]
        root_folder_id: String,
    },
    /// OneDrive / SharePoint（对齐 Go 版 drivers/onedrive，refresh_token 授权，
    /// 默认走 olist 在线刷新 API；fid 即网盘内路径）
    Onedrive {
        /// global / cn / us / de（对齐 Go 版 onedriveHostMap）
        #[serde(default = "default_onedrive_region")]
        region: String,
        /// true = SharePoint 站点（需配合 site_id），false = 个人 OneDrive
        #[serde(default)]
        is_sharepoint: bool,
        /// SharePoint 站点 id
        #[serde(default)]
        site_id: String,
        /// 根目录路径（对齐 Go 版 RootFolderPath），默认 "/"
        #[serde(default = "default_onedrive_root")]
        root_path: String,
        refresh_token: String,
        #[serde(default)]
        access_token: String,
    },
    /// Google Drive（对齐 Go 版 drivers/google_drive，refresh_token 授权，
    /// 默认走 olist 在线刷新 API；下载需 Bearer 头，仅支持服务器代理）
    GoogleDrive {
        refresh_token: String,
        #[serde(default)]
        access_token: String,
        /// 根目录文件夹 id（对齐 Go 版 RootID），留空为 "root"
        #[serde(default)]
        root_folder_id: String,
    },
    /// S3 兼容对象存储（AWS / MinIO / 七牛 / 又拍等）
    S3 {
        bucket: String,
        endpoint: String,
        #[serde(default = "default_s3_region")]
        region: String,
        access_key_id: String,
        secret_access_key: String,
        #[serde(default)]
        session_token: String,
        #[serde(default)]
        custom_host: String,
        #[serde(default)]
        force_path_style: bool,
        #[serde(default = "default_s3_expire")]
        sign_url_expire: u64,
        #[serde(default = "default_s3_root")]
        root_path: String,
    },
    /// SFTP
    Sftp {
        address: String,
        username: String,
        #[serde(default)]
        password: String,
        #[serde(default)]
        private_key: String,
        #[serde(default)]
        passphrase: String,
        #[serde(default = "default_sftp_root")]
        root_path: String,
        #[serde(default)]
        ignore_symlink_error: bool,
    },
    /// FTP
    Ftp {
        address: String,
        username: String,
        password: String,
        #[serde(default)]
        encoding: String,
        #[serde(default = "default_ftp_root")]
        root_path: String,
        #[serde(default)]
        cwd_list: bool,
    },
    /// SMB
    Smb {
        address: String,
        username: String,
        #[serde(default)]
        password: String,
        share_name: String,
        #[serde(default)]
        root_path: String,
    },
    /// AList V3 / OpenList 远程挂载
    AlistV3 {
        /// 对方站点地址，如 https://alist.example.com
        url: String,
        #[serde(default)]
        meta_password: String,
        #[serde(default)]
        username: String,
        #[serde(default)]
        password: String,
        #[serde(default)]
        token: String,
    },
    /// GitHub Releases（只读）
    GithubReleases {
        /// 多行/逗号分隔：`[path:]org/repo`
        repo_structure: String,
        #[serde(default)]
        token: String,
        #[serde(default)]
        show_all_version: bool,
        #[serde(default)]
        show_source_code: bool,
        #[serde(default)]
        gh_proxy: String,
        #[serde(default = "default_gh_per_page")]
        per_page: u32,
        #[serde(default)]
        max_page: u32,
    },

    /// PikPak
    PikPak {
        username: String,
        password: String,
        #[serde(default)]
        refresh_token: String,
        #[serde(default)]
        access_token: String,
        #[serde(default)]
        device_id: String,
    },
    /// OneDrive 分享链接
    OnedriveShare {
        url: String,
        #[serde(default)]
        password: String,
    },
    /// Dropbox
    Dropbox {
        refresh_token: String,
        #[serde(default)]
        access_token: String,
        #[serde(default)]
        root_path: String,
        #[serde(default = "default_true")]
        use_online_api: bool,
        #[serde(default)]
        client_id: String,
        #[serde(default)]
        client_secret: String,
    },
    /// Google Photos
    GooglePhoto {
        refresh_token: String,
        #[serde(default)]
        access_token: String,
        #[serde(default)]
        client_id: String,
        #[serde(default)]
        client_secret: String,
    },
    /// 115 Open（开放平台 access/refresh token）
    Pan115Open {
        access_token: String,
        refresh_token: String,
    },
    /// 115 分享（只读）
    Pan115Share {
        #[serde(default)]
        cookie: String,
        share_code: String,
        #[serde(default)]
        receive_code: String,
    },
    /// 123 Open（开放平台）
    Pan123Open {
        #[serde(default)]
        client_id: String,
        #[serde(default)]
        client_secret: String,
        #[serde(default)]
        refresh_token: String,
        #[serde(default)]
        access_token: String,
        #[serde(default = "default_true")]
        use_online_api: bool,
        #[serde(default)]
        api_address: String,
    },
    /// 123PanLink（离线直链树，只读）
    Pan123Link {
        origin_urls: String,
        #[serde(default)]
        private_key: String,
        #[serde(default)]
        uid: u64,
        #[serde(default = "default_123link_duration")]
        valid_duration: i64,
    },
    /// 阿里云盘旧版（已废弃，建议 aliyundrive_open）
    Aliyundrive {
        refresh_token: String,
        #[serde(default)]
        access_token: String,
    },
    /// 阿里云盘分享（只读）
    AliyundriveShare {
        refresh_token: String,
        #[serde(default)]
        access_token: String,
        share_id: String,
        #[serde(default)]
        share_pwd: String,
    },
    /// 夸克开放平台
    QuarkOpen {
        refresh_token: String,
        #[serde(default)]
        access_token: String,
        app_id: String,
        sign_key: String,
        #[serde(default = "default_true")]
        use_online_api: bool,
        #[serde(default)]
        api_address: String,
    },
    /// 夸克 TV（只读）
    QuarkTv {
        #[serde(default)]
        refresh_token: String,
        #[serde(default)]
        access_token: String,
        #[serde(default)]
        device_id: String,
        #[serde(default = "default_link_method")]
        link_method: String,
    },
    /// UC TV（只读）
    UcTv {
        #[serde(default)]
        refresh_token: String,
        #[serde(default)]
        access_token: String,
        #[serde(default)]
        device_id: String,
        #[serde(default = "default_link_method")]
        link_method: String,
    },
    /// PikPak 分享（只读）
    PikPakShare {
        share_id: String,
        #[serde(default)]
        share_pwd: String,
        #[serde(default = "default_platform")]
        platform: String,
        #[serde(default)]
        device_id: String,
        #[serde(default)]
        use_transcoding_address: bool,
    },
    /// OneDrive APP（Azure 应用 client_credentials + 用户邮箱）
    OnedriveApp {
        #[serde(default = "default_onedrive_region")]
        region: String,
        client_id: String,
        client_secret: String,
        #[serde(default)]
        tenant_id: String,
        email: String,
        #[serde(default)]
        custom_host: String,
        #[serde(default = "default_onedrive_root")]
        root_path: String,
    },

    // ---------- Tier 1 / Tier 2 新增驱动（对齐 OpenList-go） ----------
    /// OpenList 远程挂载（协议与 AList V3 同源 /api/fs/*）
    Openlist {
        url: String,
        #[serde(default)]
        meta_password: String,
        #[serde(default)]
        username: String,
        #[serde(default)]
        password: String,
        #[serde(default)]
        token: String,
    },
    /// OpenList 分享链接（只读）
    OpenlistShare {
        url: String,
        share_id: String,
        #[serde(default)]
        share_pwd: String,
    },
    /// 虚拟存储（测试用：生成指定数量的假文件/假文件夹，对齐 Go 版 drivers/virtual）
    Virtual {
        #[serde(default = "default_virtual_num_file")]
        num_file: u32,
        #[serde(default)]
        num_folder: u32,
    },
    /// BunnyCDN 对象存储（S3 兼容，默认端点 https://s3.bunnycdn.com）
    Bunny {
        bucket: String,
        #[serde(default)]
        endpoint: String,
        #[serde(default = "default_bunny_region")]
        region: String,
        access_key_id: String,
        secret_access_key: String,
        #[serde(default = "default_s3_root")]
        root_path: String,
    },
    /// Yandex.Disk（refresh_token 授权，默认走 olist 在线刷新 API）
    YandexDisk {
        refresh_token: String,
        #[serde(default)]
        access_token: String,
        #[serde(default = "default_true")]
        use_online_api: bool,
        #[serde(default)]
        api_address: String,
        #[serde(default)]
        client_id: String,
        #[serde(default)]
        client_secret: String,
        #[serde(default = "default_s3_root")]
        root_path: String,
    },
    /// Seafile（地址 + Token 或账号密码；repoId 留空则根目录为资料库列表）
    Seafile {
        address: String,
        #[serde(default)]
        username: String,
        #[serde(default)]
        password: String,
        #[serde(default)]
        token: String,
        #[serde(default)]
        repo_id: String,
        #[serde(default)]
        repo_pwd: String,
        #[serde(default = "default_s3_root")]
        root_path: String,
    },
    /// 可道云 KodBox（地址 + 账号密码登录获取 accessToken）
    Kodbox {
        address: String,
        #[serde(default)]
        username: String,
        #[serde(default)]
        password: String,
        #[serde(default = "default_kodbox_root")]
        root_path: String,
    },
    /// Cloudreve V4（账号密码登录或直接填 access/refresh token）
    CloudreveV4 {
        address: String,
        #[serde(default)]
        username: String,
        #[serde(default)]
        password: String,
        #[serde(default)]
        access_token: String,
        #[serde(default)]
        refresh_token: String,
        #[serde(default = "default_cloudreve_root")]
        root_path: String,
    },
    /// Terabox（国际版百度网盘，cookie 授权）
    Terabox {
        cookie: String,
        /// official（官方 dlink）或 crack（filemetas 直链）
        #[serde(default = "default_terabox_api")]
        download_api: String,
        #[serde(default = "default_s3_root")]
        root_path: String,
    },
    /// 蓝奏云优创 / 飞鸡盘（同一套接口，站点不同）
    Ilanzou {
        /// ilanzou（www.ilanzou.com）或 feijipan（www.feijipan.com）
        #[serde(default = "default_ilanzou_site")]
        site: String,
        username: String,
        password: String,
        #[serde(default = "default_ilanzou_root")]
        root_folder_id: String,
    },
    /// halalcloud OpenAPI（对齐 Go 版 drivers/halalcloud_open，HTTP 版）
    ///
    /// gRPC 版 halalcloud（OnlyProxy + NoLinkURL，下载走 slice 拼流）未移植。
    HalalcloudOpen {
        client_id: String,
        client_secret: String,
        /// 在线刷新得到的 access_token（会过期，驱动刷新后自动写回此处）
        #[serde(default)]
        access_token: String,
        /// 刷新令牌（personal API 模式下可空，但空则 access_token 失效后必须手动更新）
        #[serde(default)]
        refresh_token: String,
        #[serde(default = "default_halalcloud_host")]
        host: String,
        #[serde(default = "default_halalcloud_timeout")]
        timeout: u64,
        #[serde(default = "default_s3_root")]
        root_path: String,
    },
}

fn default_alipan_type() -> String {
    "default".to_string()
}

fn default_platform() -> String {
    "web".to_string()
}

fn default_yun139_type() -> String {
    "personal_new".to_string()
}

fn default_webdav_root() -> String {
    "/".to_string()
}

fn default_onedrive_region() -> String {
    "global".to_string()
}

fn default_onedrive_root() -> String {
    "/".to_string()
}

fn default_s3_region() -> String {
    "us-east-1".to_string()
}
fn default_gh_per_page() -> u32 {
    30
}
fn default_true() -> bool {
    true
}
fn default_123link_duration() -> i64 {
    30
}
fn default_link_method() -> String {
    "download".to_string()
}
fn default_s3_expire() -> u64 {
    4
}
fn default_s3_root() -> String {
    "/".to_string()
}
fn default_sftp_root() -> String {
    "/".to_string()
}
fn default_ftp_root() -> String {
    "/".to_string()
}
fn default_virtual_num_file() -> u32 {
    5
}
fn default_bunny_region() -> String {
    "us-east-1".to_string()
}
fn default_kodbox_root() -> String {
    "".to_string()
}
fn default_cloudreve_root() -> String {
    "/".to_string()
}
fn default_terabox_api() -> String {
    "official".to_string()
}
fn default_ilanzou_site() -> String {
    "ilanzou".to_string()
}
fn default_ilanzou_root() -> String {
    "0".to_string()
}
fn default_halalcloud_host() -> String {
    "openapi.2dland.cn".to_string()
}
fn default_halalcloud_timeout() -> u64 {
    60
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub id: String,
    pub name: String,
    #[serde(flatten)]
    pub cred: Credential,
    #[serde(default = "default_root")]
    pub root_fid: String,
    /// 服务器代理开关：true = 所有下载经本服务中转；false = 直接 302 跳转真实链接
    #[serde(default)]
    pub server_proxy: bool,
    /// 启用开关：false = 在网盘列表中隐藏此存储；默认 true
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

fn default_root() -> String {
    "0".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    pub accounts: Vec<Account>,
    /// 面板登录用户名（None/空 = 首次启动时初始化为 admin）
    #[serde(default)]
    pub web_user: Option<String>,
    /// 面板登录密码（None/空 = 首次启动时随机生成并打印到终端）
    #[serde(default)]
    pub web_pass: Option<String>,
}

/// 文件条目（驱动无关的统一模型）
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Entry {
    pub fid: String,
    pub name: String,
    pub size: u64,
    pub is_dir: bool,
    /// 毫秒时间戳
    #[serde(default)]
    pub updated_at: Option<i64>,
    // 123pan 下载接口需要的额外字段
    #[serde(default)]
    pub etag: Option<String>,
    #[serde(default)]
    pub s3_key_flag: Option<String>,
    #[serde(default)]
    pub file_type: Option<i64>,
    /// 驱动私有扩展字段（下载时需要而 list 才能拿到的信息），
    /// 前端/兼容层需原样透传（如 115 pick_code、百度 fs_id、蓝奏云分享信息等）
    #[serde(default)]
    pub extra: Option<serde_json::Value>,
}

// ---------- 持久化（redb + AES-256-GCM） ----------

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngExt;
use redb::{Database, ReadableDatabase, TableDefinition};

/// 配置表：单行 "config"，value = nonce(12B) || AES-256-GCM 密文
const CONFIG_TABLE_NAME: &str = "config";
const CONFIG_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new(CONFIG_TABLE_NAME);
const CONFIG_ROW: &str = "config";
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
/// AES-GCM 认证标签长度
const TAG_LEN: usize = 16;

pub struct Store {
    db: Database,
    key: [u8; KEY_LEN],
    pub data: Mutex<Config>,
}

impl Store {
    /// 打开数据目录：数据库 openlist.redb、密钥文件 openlist.key（缺失则自动生成）
    /// 库中无数据且目录存在旧版 config.json 时自动导入一次
    pub fn load(dir: &str) -> Self {
        let dir = PathBuf::from(dir);
        if let Err(e) = std::fs::create_dir_all(&dir) {
            panic!("无法创建数据目录 {}: {e}", dir.display());
        }
        let key = load_or_create_key(&dir);
        let db_path = dir.join("openlist.redb");
        let db = open_store_or_migrate(&db_path);

        let raw: Option<Vec<u8>> = (|| {
            let txn = db.begin_read().ok()?;
            let table = txn.open_table(CONFIG_TABLE).ok()?;
            table.get(CONFIG_ROW).ok()?.map(|v| v.value().to_vec())
        })();

        let data = match raw {
            Some(blob) => match decrypt(&key, &blob).and_then(|plain| {
                serde_json::from_slice::<Config>(&plain).map_err(|e| format!("JSON 解析失败: {e}"))
            }) {
                Ok(cfg) => cfg,
                Err(e) => panic!(
                    "数据库读取失败（{e}）：密钥文件可能与数据库不匹配，或数据已损坏: {}",
                    db_path.display()
                ),
            },
            None => import_legacy(&dir).unwrap_or_default(),
        };

        Store {
            db,
            key,
            data: Mutex::new(data),
        }
    }

    pub fn save(&self, cfg: &Config) -> std::io::Result<()> {
        let plain = serde_json::to_vec(cfg)?;
        let blob = encrypt(&self.key, &plain).map_err(io_err)?;
        let txn = self.db.begin_write().map_err(io_err)?;
        {
            let mut table = txn.open_table(CONFIG_TABLE).map_err(io_err)?;
            table.insert(CONFIG_ROW, blob.as_slice()).map_err(io_err)?;
        }
        txn.commit().map_err(io_err)?;
        Ok(())
    }

    /// 驱动回写 cookie / token
    pub fn update_credential(&self, id: &str, f: impl FnOnce(&mut Credential)) {
        let mut data = self.data.lock().unwrap();
        if let Some(acc) = data.accounts.iter_mut().find(|a| a.id == id) {
            f(&mut acc.cred);
            let _ = self.save(&data);
        }
    }

    /// 更新面板登录账号/密码（None 表示保持该项不变），加密持久化到数据库
    pub fn update_web_auth(
        &self,
        user: Option<String>,
        pass: Option<String>,
    ) -> std::io::Result<()> {
        let mut data = self.data.lock().unwrap();
        if user.is_some() {
            data.web_user = user;
        }
        if pass.is_some() {
            data.web_pass = pass;
        }
        self.save(&data)
    }
}

fn io_err<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

/// 打开数据库；若是 redb 2 时代的旧格式，先做一次性迁移再打开。
///
/// redb 4 移除了升级 API：打开 v2 文件只会返回 `DatabaseError::UpgradeRequired(2)`，
/// 项目里已经有用户的库是这个格式，直接 panic 等于升级即丢数据。
fn open_store_or_migrate(db_path: &Path) -> Database {
    match Database::create(db_path) {
        Ok(db) => db,
        Err(redb::DatabaseError::UpgradeRequired(ver)) => {
            eprintln!(
                "检测到旧版数据库格式 v{ver}（redb 2 时代），正在迁移到新格式；原文件备份为 {}",
                db_path.with_extension("redb.v2.bak").display()
            );
            migrate_legacy_store(db_path);
            Database::create(db_path)
                .unwrap_or_else(|e| panic!("迁移后仍无法打开数据库 {}: {e}", db_path.display()))
        }
        Err(e) => panic!("无法打开数据库 {}: {e}", db_path.display()),
    }
}

/// 旧库（redb 2 / 文件格式 v2）→ 新库（redb 4 / 格式 v3）一次性迁移。
///
/// 全仓库只有一张表 config（单行 "config" = nonce || AES-GCM 密文），所以把这一行原样搬过去
/// 即可（密文含 nonce，逐字节复制，密钥文件不动）。旧文件不删，改名留底：迁移是单向的，
/// 迁移后旧二进制再也读不了这个库。
fn migrate_legacy_store(db_path: &Path) {
    let tmp_path = db_path.with_extension("redb.new");
    let _ = std::fs::remove_file(&tmp_path);

    let blob: Option<Vec<u8>> = (|| -> Result<Option<Vec<u8>>, String> {
        let old = redb2::Database::create(db_path).map_err(|e| e.to_string())?;
        let txn = old.begin_read().map_err(|e| e.to_string())?;
        let table = txn
            .open_table(redb2::TableDefinition::<&str, &[u8]>::new(
                CONFIG_TABLE_NAME,
            ))
            .map_err(|e| e.to_string())?;
        let guard = table.get(CONFIG_ROW).map_err(|e| e.to_string())?;
        Ok(guard.map(|v| v.value().to_vec()))
    })()
    .unwrap_or_else(|e| panic!("读取旧版数据库 {} 失败: {e}", db_path.display()));

    if blob.is_none() {
        eprintln!("旧库中没有 config 行，按空配置迁移");
    }

    let new_db = Database::create(&tmp_path)
        .unwrap_or_else(|e| panic!("迁移时创建新库 {} 失败: {e}", tmp_path.display()));
    {
        let txn = new_db
            .begin_write()
            .unwrap_or_else(|e| panic!("迁移事务打开失败: {e}"));
        {
            let mut table = txn
                .open_table(CONFIG_TABLE)
                .unwrap_or_else(|e| panic!("迁移建表失败: {e}"));
            if let Some(b) = &blob {
                table
                    .insert(CONFIG_ROW, b.as_slice())
                    .unwrap_or_else(|e| panic!("迁移写入失败: {e}"));
            }
        }
        txn.commit().unwrap_or_else(|e| panic!("迁移提交失败: {e}"));
    }
    drop(new_db);

    let bak_path = db_path.with_extension("redb.v2.bak");
    std::fs::rename(db_path, &bak_path)
        .unwrap_or_else(|e| panic!("备份旧库到 {} 失败: {e}", bak_path.display()));
    std::fs::rename(&tmp_path, db_path)
        .unwrap_or_else(|e| panic!("用迁移后的库替换 {} 失败: {e}", db_path.display()));
}

fn encrypt(key: &[u8; KEY_LEN], plain: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new(key.into());
    let mut nonce = [0u8; NONCE_LEN];
    rand::rng().fill(&mut nonce);
    // aead 0.6 / hybrid-array 0.4：Nonce::from_slice 已弃用，改走 From/TryFrom
    let nonce_ref: &Nonce<_> = (&nonce).into();
    let ct = cipher
        .encrypt(nonce_ref, plain)
        .map_err(|_| "加密失败".to_string())?;
    let mut blob = nonce.to_vec();
    blob.extend_from_slice(&ct);
    Ok(blob)
}

fn decrypt(key: &[u8; KEY_LEN], blob: &[u8]) -> Result<Vec<u8>, String> {
    if blob.len() < NONCE_LEN + TAG_LEN {
        return Err("数据长度不足".into());
    }
    let (nonce, ct) = blob.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new(key.into());
    let nonce_ref: &Nonce<_> = nonce
        .try_into()
        .map_err(|_| format!("nonce 长度不是 {NONCE_LEN} 字节"))?;
    cipher
        .decrypt(nonce_ref, ct)
        .map_err(|_| "解密失败".to_string())
}

/// 读取 openlist.key；不存在则生成随机 32 字节密钥并写回（Unix 下权限 0600）
fn load_or_create_key(dir: &Path) -> [u8; KEY_LEN] {
    let path = dir.join("openlist.key");
    if path.exists() {
        let s = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("无法读取密钥文件 {}: {e}", path.display()));
        let bytes = hex::decode(s.trim())
            .unwrap_or_else(|e| panic!("密钥文件 {} 不是合法 hex: {e}", path.display()));
        bytes
            .try_into()
            .unwrap_or_else(|_| panic!("密钥文件 {} 长度错误（需 64 位 hex 字符）", path.display()))
    } else {
        let mut key = [0u8; KEY_LEN];
        rand::rng().fill(&mut key);
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(&path)
            .unwrap_or_else(|e| panic!("无法创建密钥文件 {}: {e}", path.display()));
        use std::io::Write;
        f.write_all(hex::encode(key).as_bytes())
            .unwrap_or_else(|e| panic!("无法写入密钥文件 {}: {e}", path.display()));
        println!("已生成加密密钥文件: {}", path.display());
        key
    }
}

/// 导入旧版 config.json（升级后首次运行触发）；原文件保留，确认无误后可手动删除
fn import_legacy(dir: &Path) -> Option<Config> {
    let path = dir.join("config.json");
    let bytes = std::fs::read(&path).ok()?;
    match serde_json::from_slice::<Config>(&bytes) {
        Ok(cfg) => {
            println!(
                "已从旧版 config.json 导入 {} 个账号；原文件保留在 {}，确认无误后可手动删除",
                cfg.accounts.len(),
                path.display()
            );
            Some(cfg)
        }
        Err(e) => {
            eprintln!("旧版 config.json 解析失败，已忽略: {e}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// redb 2（文件格式 v2）→ redb 4（格式 v3）迁移：行字节必须逐字节保留，旧文件留备份。
    /// 用 redb2 造真实旧格式库，不依赖外部文件。
    #[test]
    fn test_legacy_v2_store_migrates_without_data_loss() {
        let dir = std::env::temp_dir().join(format!("olrs-migrate-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("openlist.redb");
        let _ = std::fs::remove_file(&path);
        let payload = b"nonce-and-aes-gcm-ciphertext".to_vec();
        {
            let old = redb2::Database::create(&path).unwrap();
            let txn = old.begin_write().unwrap();
            {
                let mut t = txn
                    .open_table(redb2::TableDefinition::<&str, &[u8]>::new(
                        CONFIG_TABLE_NAME,
                    ))
                    .unwrap();
                t.insert(CONFIG_ROW, payload.as_slice()).unwrap();
            }
            txn.commit().unwrap();
        }
        assert!(
            Database::create(&path).is_err(),
            "v2 格式库在新版 redb 下应当打不开（UpgradeRequired）"
        );

        migrate_legacy_store(&path);

        assert!(
            path.with_extension("redb.v2.bak").exists(),
            "旧库应留 .v2.bak 备份"
        );
        let db = Database::create(&path).unwrap();
        let txn = db.begin_read().unwrap();
        let table = txn.open_table(CONFIG_TABLE).unwrap();
        let got = table.get(CONFIG_ROW).unwrap().map(|v| v.value().to_vec());
        assert_eq!(
            got.as_deref(),
            Some(payload.as_slice()),
            "迁移后 config 行字节必须完全一致"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_encrypt_decrypt_round_trip() {
        let key = [7u8; KEY_LEN];
        let plain = b"openlist credential payload".to_vec();
        let blob = encrypt(&key, &plain).unwrap();
        assert_ne!(blob, plain, "密文不能等于明文");
        assert!(blob.len() > plain.len(), "密文应含 nonce + tag");
        assert_eq!(decrypt(&key, &blob).unwrap(), plain);
    }

    #[test]
    fn test_encrypt_uses_fresh_nonce() {
        let key = [7u8; KEY_LEN];
        let a = encrypt(&key, b"same input").unwrap();
        let b = encrypt(&key, b"same input").unwrap();
        assert_ne!(a, b, "每次加密应使用独立 nonce");
        assert_eq!(decrypt(&key, &a).unwrap(), decrypt(&key, &b).unwrap());
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let blob = encrypt(&[1u8; KEY_LEN], b"secret").unwrap();
        assert!(decrypt(&[2u8; KEY_LEN], &blob).is_err());
    }

    #[test]
    fn test_decrypt_tampered_blob_fails() {
        let key = [3u8; KEY_LEN];
        let mut blob = encrypt(&key, b"secret").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert!(decrypt(&key, &blob).is_err(), "GCM 应校验完整性");
    }

    #[test]
    fn test_decrypt_short_blob_fails() {
        let key = [1u8; KEY_LEN];
        assert!(decrypt(&key, &[]).is_err());
        assert!(decrypt(&key, &[0u8; NONCE_LEN]).is_err());
        assert!(decrypt(&key, &[0u8; NONCE_LEN + TAG_LEN - 1]).is_err());
    }

    /// 密钥文件：首次生成、再次读取一致，Unix 下权限 0600
    #[test]
    fn test_load_or_create_key_round_trip() {
        let dir = std::env::temp_dir().join(format!("ol-rs-key-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let k1 = load_or_create_key(&dir);
        let k2 = load_or_create_key(&dir);
        assert_eq!(k1, k2);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(dir.join("openlist.key")).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
