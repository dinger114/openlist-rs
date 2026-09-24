pub mod alist_v3;
pub mod aliyundrive;
pub mod aliyundrive_open;
pub mod aliyundrive_share;
pub mod baidu_netdisk;
pub mod cloudreve_v4;
pub mod dropbox;
pub mod ftp;
pub mod github_releases;
pub mod google_drive;
pub mod google_photo;
pub mod ilanzou;
pub mod kodbox;
pub mod lanzou;
pub mod link123;
pub mod local;
pub mod onedrive;
pub mod onedrive_app;
pub mod onedrive_share;
pub mod openlist_share;
pub mod pan115;
pub mod pan115_open;
pub mod pan115_share;
pub mod pan123;
pub mod pan123_open;
pub mod pan139;
pub mod pan189;
pub mod pikpak;
pub mod pikpak_share;
pub mod quark;
pub mod quark_open;
pub mod quark_uc_tv;
pub mod s3;
pub mod seafile;
pub mod sftp;
pub mod share123;
pub mod smb;
pub mod terabox;
pub mod thunder;
pub mod virtual_driver;
pub mod webdav;
pub mod weiyun;
pub mod yandex_disk;

use crate::config::{Credential, Entry, Store};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::AsyncRead;

/// 直链信息：url + 抓取该直链所需请求头 + 是否需要代理
#[derive(Debug, Clone, serde::Serialize)]
pub struct DownloadInfo {
    pub url: String,
    pub headers: Vec<(String, String)>,
    /// true = 浏览器无法直接访问（需要带 Cookie 等头），必须走后端 /api/stream
    pub proxy: bool,
    /// 本机存储专用：非空时后端直接从磁盘流式读取（url 不使用）
    #[serde(skip)]
    pub local_path: Option<String>,
}

/// 上传输入：文件名 + 大小 + 内容流（对齐 Go 版 stream.FileStream 的最小集）
pub struct PutInput {
    pub name: String,
    pub size: u64,
    /// 上传内容流（/api/fs/put 原始 body 或 /api/fs/form 解出的文件流）
    pub reader: Pin<Box<dyn AsyncRead + Send>>,
}

/// 包装 reader，把已读字节数累加到 progress（上传进度上报）
pub struct ProgressReader<R> {
    inner: R,
    progress: Arc<AtomicU64>,
}

impl<R> ProgressReader<R> {
    pub fn new(inner: R, progress: Arc<AtomicU64>) -> Self {
        ProgressReader { inner, progress }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for ProgressReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let _ = Pin::new(&mut self.inner).poll_read(cx, buf)?;
        let after = buf.filled().len();
        if after > before {
            self.progress
                .fetch_add((after - before) as u64, Ordering::Relaxed);
        }
        std::task::Poll::Ready(Ok(()))
    }
}

pub enum Driver {
    Quark(quark::QuarkOrUC),
    QuarkUC(quark::QuarkOrUC),
    Pan123(pan123::Pan123),
    AliyundriveOpen(aliyundrive_open::AliyundriveOpen),
    BaiduNetdisk(baidu_netdisk::BaiduNetdisk),
    Pan115(pan115::Pan115),
    Thunder(thunder::Thunder),
    Lanzou(lanzou::Lanzou),
    Yun139(pan139::Yun139),
    Cloud189(pan189::Cloud189),
    Local(local::Local),
    Webdav(webdav::Webdav),
    Pan123Share(share123::Pan123Share),
    Weiyun(weiyun::Weiyun),
    Onedrive(onedrive::Onedrive),
    GoogleDrive(google_drive::GoogleDrive),
    S3(s3::S3),
    Sftp(sftp::Sftp),
    Ftp(ftp::Ftp),
    Smb(smb::Smb),
    AlistV3(alist_v3::AlistV3),
    GithubReleases(github_releases::GithubReleases),
    PikPak(pikpak::PikPak),
    OnedriveShare(onedrive_share::OnedriveShare),
    Dropbox(dropbox::Dropbox),
    GooglePhoto(google_photo::GooglePhoto),
    Pan115Open(pan115_open::Pan115Open),
    Pan115Share(pan115_share::Pan115Share),
    Pan123Open(pan123_open::Pan123Open),
    Pan123Link(link123::Pan123Link),
    Aliyundrive(aliyundrive::Aliyundrive),
    AliyundriveShare(aliyundrive_share::AliyundriveShare),
    QuarkOpen(quark_open::QuarkOpen),
    QuarkTv(quark_uc_tv::QuarkUcTv),
    UcTv(quark_uc_tv::QuarkUcTv),
    PikPakShare(pikpak_share::PikPakShare),
    OnedriveApp(onedrive_app::OnedriveApp),
    Openlist(alist_v3::AlistV3),
    OpenlistShare(openlist_share::OpenlistShare),
    Virtual(virtual_driver::Virtual),
    Bunny(s3::S3),
    YandexDisk(yandex_disk::YandexDisk),
    Seafile(seafile::Seafile),
    Kodbox(kodbox::Kodbox),
    CloudreveV4(cloudreve_v4::CloudreveV4),
    Terabox(terabox::Terabox),
    Ilanzou(ilanzou::Ilanzou),
}

impl Driver {
    /// 由账号构建驱动实例并验证凭据
    pub async fn new(id: &str, cred: &Credential, store: Arc<Store>) -> Result<Self, String> {
        let d = match cred {
            Credential::Quark { cookie } => {
                Driver::Quark(quark::QuarkOrUC::new(id, cookie.clone(), store))
            }
            Credential::QuarkUC { cookie } => {
                Driver::QuarkUC(quark::QuarkOrUC::new_uc(id, cookie.clone(), store))
            }
            Credential::Pan123 {
                username,
                password,
                access_token,
                platform,
            } => Driver::Pan123(pan123::Pan123::new(
                id,
                username.clone(),
                password.clone(),
                access_token.clone(),
                platform.clone(),
                store,
            )),
            Credential::AliyundriveOpen {
                refresh_token,
                access_token,
                alipan_type,
            } => Driver::AliyundriveOpen(aliyundrive_open::AliyundriveOpen::new(
                id,
                refresh_token.clone(),
                access_token.clone(),
                alipan_type.clone(),
                store,
            )),
            Credential::BaiduNetdisk {
                refresh_token,
                access_token,
            } => Driver::BaiduNetdisk(baidu_netdisk::BaiduNetdisk::new(
                id,
                refresh_token.clone(),
                access_token.clone(),
                store,
            )),
            Credential::Pan115 { cookie } => Driver::Pan115(pan115::Pan115::new(cookie.clone())),
            Credential::Thunder {
                username,
                password,
                refresh_token,
                captcha_token,
                device_id,
            } => Driver::Thunder(thunder::Thunder::new(
                id,
                username.clone(),
                password.clone(),
                refresh_token.clone(),
                captcha_token.clone(),
                device_id.clone(),
                store,
            )),
            Credential::Lanzou {
                cookie,
                account,
                password,
            } => Driver::Lanzou(lanzou::Lanzou::new(
                cookie.clone(),
                account.clone(),
                password.clone(),
            )),
            Credential::Yun139 {
                authorization,
                drive_type,
            } => Driver::Yun139(pan139::Yun139::new(
                id,
                authorization.clone(),
                drive_type.clone(),
                store,
            )),
            Credential::Cloud189 {
                username, password, ..
            } => Driver::Cloud189(pan189::Cloud189::new(username.clone(), password.clone())),
            Credential::Local { root_path } => Driver::Local(local::Local::new(root_path.clone())),
            Credential::Webdav {
                url,
                username,
                password,
                root_path,
            } => Driver::Webdav(webdav::Webdav::new(
                url.clone(),
                username.clone(),
                password.clone(),
                root_path.clone(),
            )),
            Credential::Pan123Share {
                share_key,
                share_pwd,
                access_token,
            } => Driver::Pan123Share(share123::Pan123Share::new(
                share_key.clone(),
                share_pwd.clone(),
                access_token.clone(),
            )),
            Credential::Weiyun {
                cookies,
                root_folder_id,
            } => Driver::Weiyun(weiyun::Weiyun::new(cookies.clone(), root_folder_id.clone())),
            Credential::Onedrive {
                region,
                is_sharepoint,
                site_id,
                root_path,
                refresh_token,
                access_token,
            } => Driver::Onedrive(onedrive::Onedrive::new(
                id,
                onedrive::OnedriveConfig {
                    region: region.clone(),
                    is_sharepoint: *is_sharepoint,
                    site_id: site_id.clone(),
                    root_path: root_path.clone(),
                    refresh_token: refresh_token.clone(),
                    access_token: access_token.clone(),
                },
                store,
            )),
            Credential::GoogleDrive {
                refresh_token,
                access_token,
                root_folder_id,
            } => Driver::GoogleDrive(google_drive::GoogleDrive::new(
                id,
                refresh_token.clone(),
                access_token.clone(),
                root_folder_id.clone(),
                store,
            )),
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
            } => Driver::S3(s3::S3::new(
                bucket.clone(),
                endpoint.clone(),
                region.clone(),
                access_key_id.clone(),
                secret_access_key.clone(),
                session_token.clone(),
                custom_host.clone(),
                *force_path_style,
                *sign_url_expire,
                root_path.clone(),
            )),
            Credential::Sftp {
                address,
                username,
                password,
                private_key,
                passphrase,
                root_path,
                ignore_symlink_error,
            } => Driver::Sftp(sftp::Sftp::new(
                address.clone(),
                username.clone(),
                password.clone(),
                private_key.clone(),
                passphrase.clone(),
                root_path.clone(),
                *ignore_symlink_error,
            )),
            Credential::Ftp {
                address,
                username,
                password,
                encoding,
                root_path,
                cwd_list,
            } => Driver::Ftp(ftp::Ftp::new(
                address.clone(),
                username.clone(),
                password.clone(),
                encoding.clone(),
                root_path.clone(),
                *cwd_list,
            )),
            Credential::Smb {
                address,
                username,
                password,
                share_name,
                root_path,
            } => Driver::Smb(smb::Smb::new(
                address.clone(),
                username.clone(),
                password.clone(),
                share_name.clone(),
                root_path.clone(),
            )),
            Credential::AlistV3 {
                url,
                meta_password,
                username,
                password,
                token,
            } => Driver::AlistV3(alist_v3::AlistV3::new(
                url.clone(),
                meta_password.clone(),
                username.clone(),
                password.clone(),
                token.clone(),
            )),
            Credential::GithubReleases {
                repo_structure,
                token,
                show_all_version,
                show_source_code,
                gh_proxy,
                per_page,
                max_page,
            } => Driver::GithubReleases(github_releases::GithubReleases::new(
                repo_structure.clone(),
                token.clone(),
                *show_all_version,
                *show_source_code,
                gh_proxy.clone(),
                *per_page,
                *max_page,
            )),
            Credential::PikPak {
                username,
                password,
                refresh_token,
                access_token,
                device_id,
            } => Driver::PikPak(pikpak::PikPak::new(
                id,
                username.clone(),
                password.clone(),
                refresh_token.clone(),
                access_token.clone(),
                device_id.clone(),
                store.clone(),
            )),
            Credential::OnedriveShare { url, password } => Driver::OnedriveShare(
                onedrive_share::OnedriveShare::new(url.clone(), password.clone()),
            ),
            Credential::Dropbox {
                refresh_token,
                access_token,
                root_path,
                use_online_api,
                client_id,
                client_secret,
            } => Driver::Dropbox(dropbox::Dropbox::new(
                id,
                refresh_token.clone(),
                access_token.clone(),
                root_path.clone(),
                *use_online_api,
                client_id.clone(),
                client_secret.clone(),
                store.clone(),
            )),
            Credential::GooglePhoto {
                refresh_token,
                access_token,
                client_id,
                client_secret,
            } => Driver::GooglePhoto(google_photo::GooglePhoto::new(
                id,
                refresh_token.clone(),
                access_token.clone(),
                client_id.clone(),
                client_secret.clone(),
                store.clone(),
            )),
            Credential::Pan115Open {
                access_token,
                refresh_token,
            } => Driver::Pan115Open(pan115_open::Pan115Open::new(
                id,
                access_token.clone(),
                refresh_token.clone(),
                store.clone(),
            )),
            Credential::Pan115Share {
                cookie,
                share_code,
                receive_code,
            } => Driver::Pan115Share(pan115_share::Pan115Share::new(
                cookie.clone(),
                share_code.clone(),
                receive_code.clone(),
            )),
            Credential::Pan123Open {
                client_id,
                client_secret,
                refresh_token,
                access_token,
                use_online_api,
                api_address,
            } => Driver::Pan123Open(pan123_open::Pan123Open::new(
                id,
                client_id.clone(),
                client_secret.clone(),
                refresh_token.clone(),
                access_token.clone(),
                *use_online_api,
                api_address.clone(),
                store.clone(),
            )),
            Credential::Pan123Link {
                origin_urls,
                private_key,
                uid,
                valid_duration,
            } => Driver::Pan123Link(link123::Pan123Link::new(
                origin_urls.clone(),
                private_key.clone(),
                *uid,
                *valid_duration,
            )?),
            Credential::Aliyundrive {
                refresh_token,
                access_token,
            } => Driver::Aliyundrive(aliyundrive::Aliyundrive::new(
                id,
                refresh_token.clone(),
                access_token.clone(),
                store.clone(),
            )),
            Credential::AliyundriveShare {
                refresh_token,
                share_id,
                share_pwd,
                ..
            } => Driver::AliyundriveShare(aliyundrive_share::AliyundriveShare::new(
                id,
                refresh_token.clone(),
                share_id.clone(),
                share_pwd.clone(),
                store.clone(),
            )),
            Credential::QuarkOpen {
                refresh_token,
                access_token,
                app_id,
                sign_key,
                use_online_api,
                api_address,
            } => Driver::QuarkOpen(quark_open::QuarkOpen::new(
                id,
                refresh_token.clone(),
                access_token.clone(),
                app_id.clone(),
                sign_key.clone(),
                *use_online_api,
                api_address.clone(),
                store.clone(),
            )),
            Credential::QuarkTv {
                refresh_token,
                access_token,
                device_id,
                link_method,
            } => Driver::QuarkTv(quark_uc_tv::QuarkUcTv::new_quark_tv(
                id,
                refresh_token.clone(),
                access_token.clone(),
                device_id.clone(),
                link_method.clone(),
                store.clone(),
            )),
            Credential::UcTv {
                refresh_token,
                access_token,
                device_id,
                link_method,
            } => Driver::UcTv(quark_uc_tv::QuarkUcTv::new_uc_tv(
                id,
                refresh_token.clone(),
                access_token.clone(),
                device_id.clone(),
                link_method.clone(),
                store.clone(),
            )),
            Credential::PikPakShare {
                share_id,
                share_pwd,
                platform,
                device_id,
                use_transcoding_address,
            } => Driver::PikPakShare(pikpak_share::PikPakShare::new(
                share_id.clone(),
                share_pwd.clone(),
                platform.clone(),
                device_id.clone(),
                *use_transcoding_address,
            )),
            Credential::OnedriveApp {
                region,
                client_id,
                client_secret,
                tenant_id,
                email,
                custom_host,
                root_path,
            } => Driver::OnedriveApp(onedrive_app::OnedriveApp::new(
                region.clone(),
                client_id.clone(),
                client_secret.clone(),
                tenant_id.clone(),
                email.clone(),
                custom_host.clone(),
                root_path.clone(),
            )),
            // OpenList 与 AList V3 协议同源（/api/fs/*），直接复用 AlistV3 实现
            Credential::Openlist {
                url,
                meta_password,
                username,
                password,
                token,
            } => Driver::Openlist(alist_v3::AlistV3::new(
                url.clone(),
                meta_password.clone(),
                username.clone(),
                password.clone(),
                token.clone(),
            )),
            Credential::OpenlistShare {
                url,
                share_id,
                share_pwd,
            } => Driver::OpenlistShare(openlist_share::OpenlistShare::new(
                url.clone(),
                share_id.clone(),
                share_pwd.clone(),
            )),
            Credential::Virtual {
                num_file,
                num_folder,
            } => Driver::Virtual(virtual_driver::Virtual::new(*num_file, *num_folder)),
            // BunnyCDN 走 S3 兼容协议，默认端点 https://s3.bunnycdn.com
            Credential::Bunny {
                bucket,
                endpoint,
                region,
                access_key_id,
                secret_access_key,
                root_path,
            } => Driver::Bunny(s3::S3::new(
                bucket.clone(),
                if endpoint.is_empty() {
                    "https://s3.bunnycdn.com".to_string()
                } else {
                    endpoint.clone()
                },
                region.clone(),
                access_key_id.clone(),
                secret_access_key.clone(),
                String::new(),
                String::new(),
                false,
                4,
                root_path.clone(),
            )),
            Credential::YandexDisk {
                refresh_token,
                access_token,
                use_online_api,
                api_address,
                client_id,
                client_secret,
                root_path,
            } => Driver::YandexDisk(yandex_disk::YandexDisk::new(
                id,
                refresh_token.clone(),
                access_token.clone(),
                *use_online_api,
                api_address.clone(),
                client_id.clone(),
                client_secret.clone(),
                root_path.clone(),
                store.clone(),
            )),
            Credential::Seafile {
                address,
                username,
                password,
                token,
                repo_id,
                repo_pwd,
                root_path,
            } => Driver::Seafile(seafile::Seafile::new(
                id,
                address.clone(),
                username.clone(),
                password.clone(),
                token.clone(),
                repo_id.clone(),
                repo_pwd.clone(),
                root_path.clone(),
                store.clone(),
            )),
            Credential::Kodbox {
                address,
                username,
                password,
                root_path,
            } => Driver::Kodbox(kodbox::Kodbox::new(
                address.clone(),
                username.clone(),
                password.clone(),
                root_path.clone(),
            )),
            Credential::CloudreveV4 {
                address,
                username,
                password,
                access_token,
                refresh_token,
                root_path,
            } => Driver::CloudreveV4(cloudreve_v4::CloudreveV4::new(
                id,
                address.clone(),
                username.clone(),
                password.clone(),
                access_token.clone(),
                refresh_token.clone(),
                root_path.clone(),
                store.clone(),
            )),
            Credential::Terabox {
                cookie,
                download_api,
                root_path,
            } => Driver::Terabox(terabox::Terabox::new(
                cookie.clone(),
                download_api.clone(),
                root_path.clone(),
            )),
            Credential::Ilanzou {
                site,
                username,
                password,
                root_folder_id,
            } => Driver::Ilanzou(ilanzou::Ilanzou::new(
                id,
                site.clone(),
                username.clone(),
                password.clone(),
                root_folder_id.clone(),
                store.clone(),
            )),
        };
        // 统一验证凭据（对齐各驱动 Init()）
        match &d {
            Driver::Quark(x) | Driver::QuarkUC(x) => x.validate().await?,
            Driver::Pan123(x) => x.validate().await?,
            Driver::AliyundriveOpen(x) => x.validate().await?,
            Driver::BaiduNetdisk(x) => x.validate().await?,
            Driver::Pan115(x) => x.validate().await?,
            Driver::Thunder(x) => x.validate().await?,
            Driver::Lanzou(x) => x.validate().await?,
            Driver::Yun139(x) => x.validate().await?,
            Driver::Cloud189(x) => x.validate().await?,
            Driver::Local(x) => x.validate()?,
            Driver::Webdav(x) => x.validate().await?,
            Driver::Pan123Share(x) => x.validate()?,
            Driver::Weiyun(x) => x.validate().await?,
            Driver::Onedrive(x) => x.validate().await?,
            Driver::GoogleDrive(x) => x.validate().await?,
            Driver::S3(x) => x.validate().await?,
            Driver::Sftp(x) => x.validate().await?,
            Driver::Ftp(x) => x.validate().await?,
            Driver::Smb(x) => x.validate().await?,
            Driver::AlistV3(x) => x.validate().await?,
            Driver::GithubReleases(x) => x.validate().await?,
            Driver::PikPak(x) => x.validate().await?,
            Driver::OnedriveShare(x) => x.validate().await?,
            Driver::Dropbox(x) => x.validate().await?,
            Driver::GooglePhoto(x) => x.validate().await?,
            Driver::Pan115Open(x) => x.validate().await?,
            Driver::Pan115Share(x) => x.validate().await?,
            Driver::Pan123Open(x) => x.validate().await?,
            Driver::Pan123Link(x) => x.validate()?,
            Driver::Aliyundrive(x) => x.validate().await?,
            Driver::AliyundriveShare(x) => x.validate().await?,
            Driver::QuarkOpen(x) => x.validate().await?,
            Driver::QuarkTv(x) => x.validate().await?,
            Driver::UcTv(x) => x.validate().await?,
            Driver::PikPakShare(x) => x.validate().await?,
            Driver::OnedriveApp(x) => x.validate().await?,
            Driver::Openlist(x) => x.validate().await?,
            Driver::OpenlistShare(x) => x.validate().await?,
            Driver::Virtual(x) => x.validate()?,
            Driver::Bunny(x) => x.validate().await?,
            Driver::YandexDisk(x) => x.validate().await?,
            Driver::Seafile(x) => x.validate().await?,
            Driver::Kodbox(x) => x.validate().await?,
            Driver::CloudreveV4(x) => x.validate().await?,
            Driver::Terabox(x) => x.validate().await?,
            Driver::Ilanzou(x) => x.validate().await?,
        }
        Ok(d)
    }

    pub async fn list(&self, parent_fid: &str) -> Result<Vec<Entry>, String> {
        match self {
            Driver::Quark(d) | Driver::QuarkUC(d) => d.list(parent_fid).await,
            Driver::Pan123(d) => d.list(parent_fid).await,
            Driver::AliyundriveOpen(d) => d.list(parent_fid).await,
            Driver::BaiduNetdisk(d) => d.list(parent_fid).await,
            Driver::Pan115(d) => d.list(parent_fid).await,
            Driver::Thunder(d) => d.list(parent_fid).await,
            Driver::Lanzou(d) => d.list(parent_fid).await,
            Driver::Yun139(d) => d.list(parent_fid).await,
            Driver::Cloud189(d) => d.list(parent_fid).await,
            Driver::Local(d) => d.list(parent_fid),
            Driver::Webdav(d) => d.list(parent_fid).await,
            Driver::Pan123Share(d) => d.list(parent_fid).await,
            Driver::Weiyun(d) => d.list(parent_fid).await,
            Driver::Onedrive(d) => d.list(parent_fid).await,
            Driver::GoogleDrive(d) => d.list(parent_fid).await,
            Driver::S3(d) => d.list(parent_fid).await,
            Driver::Sftp(d) => d.list(parent_fid).await,
            Driver::Ftp(d) => d.list(parent_fid).await,
            Driver::Smb(d) => d.list(parent_fid).await,
            Driver::AlistV3(d) => d.list(parent_fid).await,
            Driver::GithubReleases(d) => d.list(parent_fid).await,
            Driver::PikPak(d) => d.list(parent_fid).await,
            Driver::OnedriveShare(d) => d.list(parent_fid).await,
            Driver::Dropbox(d) => d.list(parent_fid).await,
            Driver::GooglePhoto(d) => d.list(parent_fid).await,
            Driver::Pan115Open(d) => d.list(parent_fid).await,
            Driver::Pan115Share(d) => d.list(parent_fid).await,
            Driver::Pan123Open(d) => d.list(parent_fid).await,
            Driver::Pan123Link(d) => d.list(parent_fid).await,
            Driver::Aliyundrive(d) => d.list(parent_fid).await,
            Driver::AliyundriveShare(d) => d.list(parent_fid).await,
            Driver::QuarkOpen(d) => d.list(parent_fid).await,
            Driver::QuarkTv(d) => d.list(parent_fid).await,
            Driver::UcTv(d) => d.list(parent_fid).await,
            Driver::PikPakShare(d) => d.list(parent_fid).await,
            Driver::OnedriveApp(d) => d.list(parent_fid).await,
            Driver::Openlist(d) => d.list(parent_fid).await,
            Driver::OpenlistShare(d) => d.list(parent_fid).await,
            Driver::Virtual(d) => d.list(parent_fid).await,
            Driver::Bunny(d) => d.list(parent_fid).await,
            Driver::YandexDisk(d) => d.list(parent_fid).await,
            Driver::Seafile(d) => d.list(parent_fid).await,
            Driver::Kodbox(d) => d.list(parent_fid).await,
            Driver::CloudreveV4(d) => d.list(parent_fid).await,
            Driver::Terabox(d) => d.list(parent_fid).await,
            Driver::Ilanzou(d) => d.list(parent_fid).await,
        }
    }

    pub async fn download(&self, e: &Entry) -> Result<DownloadInfo, String> {
        match self {
            Driver::Quark(d) | Driver::QuarkUC(d) => d.download(e).await,
            Driver::Pan123(d) => d.download(e).await,
            Driver::AliyundriveOpen(d) => d.download(e).await,
            Driver::BaiduNetdisk(d) => d.download(e).await,
            Driver::Pan115(d) => d.download(e).await,
            Driver::Thunder(d) => d.download(e).await,
            Driver::Lanzou(d) => d.download(e).await,
            Driver::Yun139(d) => d.download(e).await,
            Driver::Cloud189(d) => d.download(e).await,
            Driver::Local(d) => d.download(e),
            Driver::Webdav(d) => d.download(e).await,
            Driver::Pan123Share(d) => d.download(e).await,
            Driver::Weiyun(d) => d.download(e).await,
            Driver::Onedrive(d) => d.download(e).await,
            Driver::GoogleDrive(d) => d.download(e).await,
            Driver::S3(d) => d.download(e).await,
            Driver::Sftp(d) => d.download(e).await,
            Driver::Ftp(d) => d.download(e).await,
            Driver::Smb(d) => d.download(e).await,
            Driver::AlistV3(d) => d.download(e).await,
            Driver::GithubReleases(d) => d.download(e).await,
            Driver::PikPak(d) => d.download(e).await,
            Driver::OnedriveShare(d) => d.download(e).await,
            Driver::Dropbox(d) => d.download(e).await,
            Driver::GooglePhoto(d) => d.download(e).await,
            Driver::Pan115Open(d) => d.download(e).await,
            Driver::Pan115Share(d) => d.download(e).await,
            Driver::Pan123Open(d) => d.download(e).await,
            Driver::Pan123Link(d) => d.download(e).await,
            Driver::Aliyundrive(d) => d.download(e).await,
            Driver::AliyundriveShare(d) => d.download(e).await,
            Driver::QuarkOpen(d) => d.download(e).await,
            Driver::QuarkTv(d) => d.download(e).await,
            Driver::UcTv(d) => d.download(e).await,
            Driver::PikPakShare(d) => d.download(e).await,
            Driver::OnedriveApp(d) => d.download(e).await,
            Driver::Openlist(d) => d.download(e).await,
            Driver::OpenlistShare(d) => d.download(e).await,
            Driver::Virtual(d) => d.download(e).await,
            Driver::Bunny(d) => d.download(e).await,
            Driver::YandexDisk(d) => d.download(e).await,
            Driver::Seafile(d) => d.download(e).await,
            Driver::Kodbox(d) => d.download(e).await,
            Driver::CloudreveV4(d) => d.download(e).await,
            Driver::Terabox(d) => d.download(e).await,
            Driver::Ilanzou(d) => d.download(e).await,
        }
    }

    /// 新建文件夹（对齐 Go 版 MakeDir）
    pub async fn mkdir(&self, parent_fid: &str, name: &str) -> Result<(), String> {
        match self {
            Driver::Quark(d) | Driver::QuarkUC(d) => d.mkdir(parent_fid, name).await,
            Driver::Pan123(d) => d.mkdir(parent_fid, name).await,
            Driver::AliyundriveOpen(d) => d.mkdir(parent_fid, name).await,
            Driver::BaiduNetdisk(d) => d.mkdir(parent_fid, name).await,
            Driver::Pan115(d) => d.mkdir(parent_fid, name).await,
            Driver::Thunder(d) => d.mkdir(parent_fid, name).await,
            Driver::Lanzou(d) => d.mkdir(parent_fid, name).await,
            Driver::Yun139(d) => d.mkdir(parent_fid, name).await,
            Driver::Cloud189(d) => d.mkdir(parent_fid, name).await,
            Driver::Local(d) => d.mkdir(parent_fid, name),
            Driver::Webdav(d) => d.mkdir(parent_fid, name).await,
            Driver::Pan123Share(d) => d.mkdir(parent_fid, name).await,
            Driver::Weiyun(d) => d.mkdir(parent_fid, name).await,
            Driver::Onedrive(d) => d.mkdir(parent_fid, name).await,
            Driver::GoogleDrive(d) => d.mkdir(parent_fid, name).await,
            Driver::S3(d) => d.mkdir(parent_fid, name).await,
            Driver::Sftp(d) => d.mkdir(parent_fid, name).await,
            Driver::Ftp(d) => d.mkdir(parent_fid, name).await,
            Driver::Smb(d) => d.mkdir(parent_fid, name).await,
            Driver::AlistV3(d) => d.mkdir(parent_fid, name).await,
            Driver::GithubReleases(d) => d.mkdir(parent_fid, name).await,
            Driver::PikPak(d) => d.mkdir(parent_fid, name).await,
            Driver::OnedriveShare(d) => d.mkdir(parent_fid, name).await,
            Driver::Dropbox(d) => d.mkdir(parent_fid, name).await,
            Driver::GooglePhoto(d) => d.mkdir(parent_fid, name).await,
            Driver::Pan115Open(d) => d.mkdir(parent_fid, name).await,
            Driver::Pan115Share(d) => d.mkdir(parent_fid, name).await,
            Driver::Pan123Open(d) => d.mkdir(parent_fid, name).await,
            Driver::Pan123Link(d) => d.mkdir(parent_fid, name).await,
            Driver::Aliyundrive(d) => d.mkdir(parent_fid, name).await,
            Driver::AliyundriveShare(d) => d.mkdir(parent_fid, name).await,
            Driver::QuarkOpen(d) => d.mkdir(parent_fid, name).await,
            Driver::QuarkTv(d) => d.mkdir(parent_fid, name).await,
            Driver::UcTv(d) => d.mkdir(parent_fid, name).await,
            Driver::PikPakShare(d) => d.mkdir(parent_fid, name).await,
            Driver::OnedriveApp(d) => d.mkdir(parent_fid, name).await,
            Driver::Openlist(d) => d.mkdir(parent_fid, name).await,
            Driver::OpenlistShare(d) => d.mkdir(parent_fid, name).await,
            Driver::Virtual(d) => d.mkdir(parent_fid, name).await,
            Driver::Bunny(d) => d.mkdir(parent_fid, name).await,
            Driver::YandexDisk(d) => d.mkdir(parent_fid, name).await,
            Driver::Seafile(d) => d.mkdir(parent_fid, name).await,
            Driver::Kodbox(d) => d.mkdir(parent_fid, name).await,
            Driver::CloudreveV4(d) => d.mkdir(parent_fid, name).await,
            Driver::Terabox(d) => d.mkdir(parent_fid, name).await,
            Driver::Ilanzou(d) => d.mkdir(parent_fid, name).await,
        }
    }

    /// 重命名（对齐 Go 版 Rename）
    pub async fn rename(&self, parent_fid: &str, e: &Entry, new_name: &str) -> Result<(), String> {
        match self {
            Driver::Quark(d) | Driver::QuarkUC(d) => d.rename(parent_fid, e, new_name).await,
            Driver::Pan123(d) => d.rename(parent_fid, e, new_name).await,
            Driver::AliyundriveOpen(d) => d.rename(parent_fid, e, new_name).await,
            Driver::BaiduNetdisk(d) => d.rename(parent_fid, e, new_name).await,
            Driver::Pan115(d) => d.rename(parent_fid, e, new_name).await,
            Driver::Thunder(d) => d.rename(parent_fid, e, new_name).await,
            Driver::Lanzou(d) => d.rename(parent_fid, e, new_name).await,
            Driver::Yun139(d) => d.rename(parent_fid, e, new_name).await,
            Driver::Cloud189(d) => d.rename(parent_fid, e, new_name).await,
            Driver::Local(d) => d.rename(parent_fid, e, new_name),
            Driver::Webdav(d) => d.rename(parent_fid, e, new_name).await,
            Driver::Pan123Share(d) => d.rename(parent_fid, e, new_name).await,
            Driver::Weiyun(d) => d.rename(parent_fid, e, new_name).await,
            Driver::Onedrive(d) => d.rename(parent_fid, e, new_name).await,
            Driver::GoogleDrive(d) => d.rename(parent_fid, e, new_name).await,
            Driver::S3(d) => d.rename(parent_fid, e, new_name).await,
            Driver::Sftp(d) => d.rename(parent_fid, e, new_name).await,
            Driver::Ftp(d) => d.rename(parent_fid, e, new_name).await,
            Driver::Smb(d) => d.rename(parent_fid, e, new_name).await,
            Driver::AlistV3(d) => d.rename(parent_fid, e, new_name).await,
            Driver::GithubReleases(d) => d.rename(parent_fid, e, new_name).await,
            Driver::PikPak(d) => d.rename(parent_fid, e, new_name).await,
            Driver::OnedriveShare(d) => d.rename(parent_fid, e, new_name).await,
            Driver::Dropbox(d) => d.rename(parent_fid, e, new_name).await,
            Driver::GooglePhoto(d) => d.rename(parent_fid, e, new_name).await,
            Driver::Pan115Open(d) => d.rename(parent_fid, e, new_name).await,
            Driver::Pan115Share(d) => d.rename(parent_fid, e, new_name).await,
            Driver::Pan123Open(d) => d.rename(parent_fid, e, new_name).await,
            Driver::Pan123Link(d) => d.rename(parent_fid, e, new_name).await,
            Driver::Aliyundrive(d) => d.rename(parent_fid, e, new_name).await,
            Driver::AliyundriveShare(d) => d.rename(parent_fid, e, new_name).await,
            Driver::QuarkOpen(d) => d.rename(parent_fid, e, new_name).await,
            Driver::QuarkTv(d) => d.rename(parent_fid, e, new_name).await,
            Driver::UcTv(d) => d.rename(parent_fid, e, new_name).await,
            Driver::PikPakShare(d) => d.rename(parent_fid, e, new_name).await,
            Driver::OnedriveApp(d) => d.rename(parent_fid, e, new_name).await,
            Driver::Openlist(d) => d.rename(parent_fid, e, new_name).await,
            Driver::OpenlistShare(d) => d.rename(parent_fid, e, new_name).await,
            Driver::Virtual(d) => d.rename(parent_fid, e, new_name).await,
            Driver::Bunny(d) => d.rename(parent_fid, e, new_name).await,
            Driver::YandexDisk(d) => d.rename(parent_fid, e, new_name).await,
            Driver::Seafile(d) => d.rename(parent_fid, e, new_name).await,
            Driver::Kodbox(d) => d.rename(parent_fid, e, new_name).await,
            Driver::CloudreveV4(d) => d.rename(parent_fid, e, new_name).await,
            Driver::Terabox(d) => d.rename(parent_fid, e, new_name).await,
            Driver::Ilanzou(d) => d.rename(parent_fid, e, new_name).await,
        }
    }

    /// 移动（对齐 Go 版 Move）
    pub async fn move_entry(
        &self,
        parent_fid: &str,
        e: &Entry,
        dst_dir_fid: &str,
    ) -> Result<(), String> {
        match self {
            Driver::Quark(d) | Driver::QuarkUC(d) => d.move_entry(parent_fid, e, dst_dir_fid).await,
            Driver::Pan123(d) => d.move_entry(parent_fid, e, dst_dir_fid).await,
            Driver::AliyundriveOpen(d) => d.move_entry(parent_fid, e, dst_dir_fid).await,
            Driver::BaiduNetdisk(d) => d.move_entry(parent_fid, e, dst_dir_fid).await,
            Driver::Pan115(d) => d.move_entry(parent_fid, e, dst_dir_fid).await,
            Driver::Thunder(d) => d.move_entry(parent_fid, e, dst_dir_fid).await,
            Driver::Lanzou(d) => d.move_entry(parent_fid, e, dst_dir_fid).await,
            Driver::Yun139(d) => d.move_entry(parent_fid, e, dst_dir_fid).await,
            Driver::Cloud189(d) => d.move_entry(parent_fid, e, dst_dir_fid).await,
            Driver::Local(d) => d.move_entry(parent_fid, e, dst_dir_fid),
            Driver::Webdav(d) => d.move_entry(parent_fid, e, dst_dir_fid).await,
            Driver::Pan123Share(d) => d.move_entry(parent_fid, e, dst_dir_fid).await,
            Driver::Weiyun(d) => d.move_entry(parent_fid, e, dst_dir_fid).await,
            Driver::Onedrive(d) => d.move_entry(parent_fid, e, dst_dir_fid).await,
            Driver::GoogleDrive(d) => d.move_entry(parent_fid, e, dst_dir_fid).await,
            Driver::S3(d) => d.move_entry(parent_fid, e, dst_dir_fid).await,
            Driver::Sftp(d) => d.move_entry(parent_fid, e, dst_dir_fid).await,
            Driver::Ftp(d) => d.move_entry(parent_fid, e, dst_dir_fid).await,
            Driver::Smb(d) => d.move_entry(parent_fid, e, dst_dir_fid).await,
            Driver::AlistV3(d) => d.move_entry(parent_fid, e, dst_dir_fid).await,
            Driver::GithubReleases(d) => d.move_entry(parent_fid, e, dst_dir_fid).await,
            Driver::PikPak(d) => d.move_entry(parent_fid, e, dst_dir_fid).await,
            Driver::OnedriveShare(d) => d.move_entry(parent_fid, e, dst_dir_fid).await,
            Driver::Dropbox(d) => d.move_entry(parent_fid, e, dst_dir_fid).await,
            Driver::GooglePhoto(d) => d.move_entry(parent_fid, e, dst_dir_fid).await,
            Driver::Pan115Open(d) => d.move_entry(parent_fid, e, dst_dir_fid).await,
            Driver::Pan115Share(d) => d.move_entry(parent_fid, e, dst_dir_fid).await,
            Driver::Pan123Open(d) => d.move_entry(parent_fid, e, dst_dir_fid).await,
            Driver::Pan123Link(d) => d.move_entry(parent_fid, e, dst_dir_fid).await,
            Driver::Aliyundrive(d) => d.move_entry(parent_fid, e, dst_dir_fid).await,
            Driver::AliyundriveShare(d) => d.move_entry(parent_fid, e, dst_dir_fid).await,
            Driver::QuarkOpen(d) => d.move_entry(parent_fid, e, dst_dir_fid).await,
            Driver::QuarkTv(d) => d.move_entry(parent_fid, e, dst_dir_fid).await,
            Driver::UcTv(d) => d.move_entry(parent_fid, e, dst_dir_fid).await,
            Driver::PikPakShare(d) => d.move_entry(parent_fid, e, dst_dir_fid).await,
            Driver::OnedriveApp(d) => d.move_entry(parent_fid, e, dst_dir_fid).await,
            Driver::Openlist(d) => d.move_entry(parent_fid, e, dst_dir_fid).await,
            Driver::OpenlistShare(d) => d.move_entry(parent_fid, e, dst_dir_fid).await,
            Driver::Virtual(d) => d.move_entry(parent_fid, e, dst_dir_fid).await,
            Driver::Bunny(d) => d.move_entry(parent_fid, e, dst_dir_fid).await,
            Driver::YandexDisk(d) => d.move_entry(parent_fid, e, dst_dir_fid).await,
            Driver::Seafile(d) => d.move_entry(parent_fid, e, dst_dir_fid).await,
            Driver::Kodbox(d) => d.move_entry(parent_fid, e, dst_dir_fid).await,
            Driver::CloudreveV4(d) => d.move_entry(parent_fid, e, dst_dir_fid).await,
            Driver::Terabox(d) => d.move_entry(parent_fid, e, dst_dir_fid).await,
            Driver::Ilanzou(d) => d.move_entry(parent_fid, e, dst_dir_fid).await,
        }
    }

    /// 复制（对齐 Go 版 Copy；蓝奏云不支持）
    pub async fn copy(&self, parent_fid: &str, e: &Entry, dst_dir_fid: &str) -> Result<(), String> {
        match self {
            Driver::Quark(d) | Driver::QuarkUC(d) => d.copy(parent_fid, e, dst_dir_fid).await,
            Driver::Pan123(d) => d.copy(parent_fid, e, dst_dir_fid).await,
            Driver::AliyundriveOpen(d) => d.copy(parent_fid, e, dst_dir_fid).await,
            Driver::BaiduNetdisk(d) => d.copy(parent_fid, e, dst_dir_fid).await,
            Driver::Pan115(d) => d.copy(parent_fid, e, dst_dir_fid).await,
            Driver::Thunder(d) => d.copy(parent_fid, e, dst_dir_fid).await,
            Driver::Lanzou(d) => d.copy(parent_fid, e, dst_dir_fid).await,
            Driver::Yun139(d) => d.copy(parent_fid, e, dst_dir_fid).await,
            Driver::Cloud189(d) => d.copy(parent_fid, e, dst_dir_fid).await,
            Driver::Local(d) => d.copy(parent_fid, e, dst_dir_fid),
            Driver::Webdav(d) => d.copy(parent_fid, e, dst_dir_fid).await,
            Driver::Pan123Share(d) => d.copy(parent_fid, e, dst_dir_fid).await,
            Driver::Weiyun(d) => d.copy(parent_fid, e, dst_dir_fid).await,
            Driver::Onedrive(d) => d.copy(parent_fid, e, dst_dir_fid).await,
            Driver::GoogleDrive(d) => d.copy(parent_fid, e, dst_dir_fid).await,
            Driver::S3(d) => d.copy(parent_fid, e, dst_dir_fid).await,
            Driver::Sftp(d) => d.copy(parent_fid, e, dst_dir_fid).await,
            Driver::Ftp(d) => d.copy(parent_fid, e, dst_dir_fid).await,
            Driver::Smb(d) => d.copy(parent_fid, e, dst_dir_fid).await,
            Driver::AlistV3(d) => d.copy(parent_fid, e, dst_dir_fid).await,
            Driver::GithubReleases(d) => d.copy(parent_fid, e, dst_dir_fid).await,
            Driver::PikPak(d) => d.copy(parent_fid, e, dst_dir_fid).await,
            Driver::OnedriveShare(d) => d.copy(parent_fid, e, dst_dir_fid).await,
            Driver::Dropbox(d) => d.copy(parent_fid, e, dst_dir_fid).await,
            Driver::GooglePhoto(d) => d.copy(parent_fid, e, dst_dir_fid).await,
            Driver::Pan115Open(d) => d.copy(parent_fid, e, dst_dir_fid).await,
            Driver::Pan115Share(d) => d.copy(parent_fid, e, dst_dir_fid).await,
            Driver::Pan123Open(d) => d.copy(parent_fid, e, dst_dir_fid).await,
            Driver::Pan123Link(d) => d.copy(parent_fid, e, dst_dir_fid).await,
            Driver::Aliyundrive(d) => d.copy(parent_fid, e, dst_dir_fid).await,
            Driver::AliyundriveShare(d) => d.copy(parent_fid, e, dst_dir_fid).await,
            Driver::QuarkOpen(d) => d.copy(parent_fid, e, dst_dir_fid).await,
            Driver::QuarkTv(d) => d.copy(parent_fid, e, dst_dir_fid).await,
            Driver::UcTv(d) => d.copy(parent_fid, e, dst_dir_fid).await,
            Driver::PikPakShare(d) => d.copy(parent_fid, e, dst_dir_fid).await,
            Driver::OnedriveApp(d) => d.copy(parent_fid, e, dst_dir_fid).await,
            Driver::Openlist(d) => d.copy(parent_fid, e, dst_dir_fid).await,
            Driver::OpenlistShare(d) => d.copy(parent_fid, e, dst_dir_fid).await,
            Driver::Virtual(d) => d.copy(parent_fid, e, dst_dir_fid).await,
            Driver::Bunny(d) => d.copy(parent_fid, e, dst_dir_fid).await,
            Driver::YandexDisk(d) => d.copy(parent_fid, e, dst_dir_fid).await,
            Driver::Seafile(d) => d.copy(parent_fid, e, dst_dir_fid).await,
            Driver::Kodbox(d) => d.copy(parent_fid, e, dst_dir_fid).await,
            Driver::CloudreveV4(d) => d.copy(parent_fid, e, dst_dir_fid).await,
            Driver::Terabox(d) => d.copy(parent_fid, e, dst_dir_fid).await,
            Driver::Ilanzou(d) => d.copy(parent_fid, e, dst_dir_fid).await,
        }
    }

    /// 删除（对齐 Go 版 Remove）
    pub async fn remove(&self, parent_fid: &str, e: &Entry) -> Result<(), String> {
        match self {
            Driver::Quark(d) | Driver::QuarkUC(d) => d.remove(parent_fid, e).await,
            Driver::Pan123(d) => d.remove(parent_fid, e).await,
            Driver::AliyundriveOpen(d) => d.remove(parent_fid, e).await,
            Driver::BaiduNetdisk(d) => d.remove(parent_fid, e).await,
            Driver::Pan115(d) => d.remove(parent_fid, e).await,
            Driver::Thunder(d) => d.remove(parent_fid, e).await,
            Driver::Lanzou(d) => d.remove(parent_fid, e).await,
            Driver::Yun139(d) => d.remove(parent_fid, e).await,
            Driver::Cloud189(d) => d.remove(parent_fid, e).await,
            Driver::Local(d) => d.remove(parent_fid, e),
            Driver::Webdav(d) => d.remove(parent_fid, e).await,
            Driver::Pan123Share(d) => d.remove(parent_fid, e).await,
            Driver::Weiyun(d) => d.remove(parent_fid, e).await,
            Driver::Onedrive(d) => d.remove(parent_fid, e).await,
            Driver::GoogleDrive(d) => d.remove(parent_fid, e).await,
            Driver::S3(d) => d.remove(parent_fid, e).await,
            Driver::Sftp(d) => d.remove(parent_fid, e).await,
            Driver::Ftp(d) => d.remove(parent_fid, e).await,
            Driver::Smb(d) => d.remove(parent_fid, e).await,
            Driver::AlistV3(d) => d.remove(parent_fid, e).await,
            Driver::GithubReleases(d) => d.remove(parent_fid, e).await,
            Driver::PikPak(d) => d.remove(parent_fid, e).await,
            Driver::OnedriveShare(d) => d.remove(parent_fid, e).await,
            Driver::Dropbox(d) => d.remove(parent_fid, e).await,
            Driver::GooglePhoto(d) => d.remove(parent_fid, e).await,
            Driver::Pan115Open(d) => d.remove(parent_fid, e).await,
            Driver::Pan115Share(d) => d.remove(parent_fid, e).await,
            Driver::Pan123Open(d) => d.remove(parent_fid, e).await,
            Driver::Pan123Link(d) => d.remove(parent_fid, e).await,
            Driver::Aliyundrive(d) => d.remove(parent_fid, e).await,
            Driver::AliyundriveShare(d) => d.remove(parent_fid, e).await,
            Driver::QuarkOpen(d) => d.remove(parent_fid, e).await,
            Driver::QuarkTv(d) => d.remove(parent_fid, e).await,
            Driver::UcTv(d) => d.remove(parent_fid, e).await,
            Driver::PikPakShare(d) => d.remove(parent_fid, e).await,
            Driver::OnedriveApp(d) => d.remove(parent_fid, e).await,
            Driver::Openlist(d) => d.remove(parent_fid, e).await,
            Driver::OpenlistShare(d) => d.remove(parent_fid, e).await,
            Driver::Virtual(d) => d.remove(parent_fid, e).await,
            Driver::Bunny(d) => d.remove(parent_fid, e).await,
            Driver::YandexDisk(d) => d.remove(parent_fid, e).await,
            Driver::Seafile(d) => d.remove(parent_fid, e).await,
            Driver::Kodbox(d) => d.remove(parent_fid, e).await,
            Driver::CloudreveV4(d) => d.remove(parent_fid, e).await,
            Driver::Terabox(d) => d.remove(parent_fid, e).await,
            Driver::Ilanzou(d) => d.remove(parent_fid, e).await,
        }
    }

    /// 上传文件（对齐 Go 版 Put）。内容流被消耗；
    /// 上传进度由调用方在 reader 外包 ProgressReader 统计，驱动不感知。
    pub async fn put(&self, dst_dir_fid: &str, input: PutInput) -> Result<(), String> {
        match self {
            Driver::Quark(d) | Driver::QuarkUC(d) => d.put(dst_dir_fid, input).await,
            Driver::Pan123(d) => d.put(dst_dir_fid, input).await,
            Driver::AliyundriveOpen(d) => d.put(dst_dir_fid, input).await,
            Driver::BaiduNetdisk(d) => d.put(dst_dir_fid, input).await,
            Driver::Pan115(d) => d.put(dst_dir_fid, input).await,
            Driver::Thunder(d) => d.put(dst_dir_fid, input).await,
            Driver::Lanzou(d) => d.put(dst_dir_fid, input).await,
            Driver::Yun139(d) => d.put(dst_dir_fid, input).await,
            Driver::Cloud189(d) => d.put(dst_dir_fid, input).await,
            Driver::Local(d) => d.put(dst_dir_fid, input).await,
            Driver::Webdav(d) => d.put(dst_dir_fid, input).await,
            Driver::Pan123Share(d) => d.put(dst_dir_fid, input).await,
            Driver::Weiyun(d) => d.put(dst_dir_fid, input).await,
            Driver::Onedrive(d) => d.put(dst_dir_fid, input).await,
            Driver::GoogleDrive(d) => d.put(dst_dir_fid, input).await,
            Driver::S3(d) => d.put(dst_dir_fid, input).await,
            Driver::Sftp(d) => d.put(dst_dir_fid, input).await,
            Driver::Ftp(d) => d.put(dst_dir_fid, input).await,
            Driver::Smb(d) => d.put(dst_dir_fid, input).await,
            Driver::AlistV3(d) => d.put(dst_dir_fid, input).await,
            Driver::GithubReleases(d) => d.put(dst_dir_fid, input).await,
            Driver::PikPak(d) => d.put(dst_dir_fid, input).await,
            Driver::OnedriveShare(d) => d.put(dst_dir_fid, input).await,
            Driver::Dropbox(d) => d.put(dst_dir_fid, input).await,
            Driver::GooglePhoto(d) => d.put(dst_dir_fid, input).await,
            Driver::Pan115Open(d) => d.put(dst_dir_fid, input).await,
            Driver::Pan115Share(d) => d.put(dst_dir_fid, input).await,
            Driver::Pan123Open(d) => d.put(dst_dir_fid, input).await,
            Driver::Pan123Link(d) => d.put(dst_dir_fid, input).await,
            Driver::Aliyundrive(d) => d.put(dst_dir_fid, input).await,
            Driver::AliyundriveShare(d) => d.put(dst_dir_fid, input).await,
            Driver::QuarkOpen(d) => d.put(dst_dir_fid, input).await,
            Driver::QuarkTv(d) => d.put(dst_dir_fid, input).await,
            Driver::UcTv(d) => d.put(dst_dir_fid, input).await,
            Driver::PikPakShare(d) => d.put(dst_dir_fid, input).await,
            Driver::OnedriveApp(d) => d.put(dst_dir_fid, input).await,
            Driver::Openlist(d) => d.put(dst_dir_fid, input).await,
            Driver::OpenlistShare(d) => d.put(dst_dir_fid, input).await,
            Driver::Virtual(d) => d.put(dst_dir_fid, input).await,
            Driver::Bunny(d) => d.put(dst_dir_fid, input).await,
            Driver::YandexDisk(d) => d.put(dst_dir_fid, input).await,
            Driver::Seafile(d) => d.put(dst_dir_fid, input).await,
            Driver::Kodbox(d) => d.put(dst_dir_fid, input).await,
            Driver::CloudreveV4(d) => d.put(dst_dir_fid, input).await,
            Driver::Terabox(d) => d.put(dst_dir_fid, input).await,
            Driver::Ilanzou(d) => d.put(dst_dir_fid, input).await,
        }
    }
}
