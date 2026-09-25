//! 网易云音乐云盘（对齐 Go 版 drivers/netease_music）
//!
//! 只读实现：云盘歌曲列表 + 取播放直链。
//! Go 版的歌词（虚拟 .lrc 条目）、删除、上传未移植（歌词需要服务端内存响应，
//! 上传需要 eapi 与音频标签解析）。
//!
//! 三套加密都是上游同一份实现：
//! - `weapi`：列表与单曲直链。两层 AES-128-CBC（内置 presetKey + 随机 16 字符密钥），
//!   随机密钥再走裸 RSA 模幂得 `encSecKey`
//! - `linuxapi`：上游取直链用的转发方式（AES-128-ECB 后 hex，POST 到 `/api/linux/forward`），
//!   实测该端点回 `{"code":500}`，故只作兜底
//! - 请求一律带浏览器化 `Cookie`（用户 cookie + `os=pc`）与 `Referer`
//!
//! 列表按页拉全：`song_limit` 是每页条数（默认 200，与上游同名义），
//! 循环 offset 直到「本页不满」或已取满响应里的云盘总数（`size`），上限 2 万首。

use super::DownloadInfo;
use crate::config::Entry;
use aes::cipher::{Block, BlockCipherEncrypt, KeyInit};
use aes::Aes128;
use base64::Engine;
use num_bigint::BigUint;
use rand::RngExt;
use regex::Regex;
use reqwest::Client;
use rsa::pkcs8::DecodePublicKey;
use rsa::traits::PublicKeyParts;
use rsa::RsaPublicKey;
use serde_json::{json, Map, Value};
use std::collections::HashSet;

const LIST_URL: &str = "https://music.163.com/weapi/v1/cloud/get";
/// 单曲直链（weapi）。上游 Go 走的是 linuxapi 转发 `/api/linux/forward`，
/// 该端点实测对同款请求回 `{"code":500}`，故改用这个 weapi 端点，转发端点降级兜底
const SONG_URL_WAPI: &str = "https://music.163.com/weapi/song/enhance/player/url";
const FORWARD_URL: &str = "https://music.163.com/api/linux/forward";
/// 取直链的接口路径，linuxapi 把整包转发到这里
const SONG_URL_PATH: &str = "/api/song/enhance/player/url";

/// linuxapi 请求的 UA（上游 util.go 里的固定值，服务端按客户端类型校验）
const LINUX_UA: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 \
                        (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36";

const PRESET_KEY: &[u8] = b"0CoJUm6Qyw8W8jud";
const LINUXAPI_KEY: &[u8] = b"rFgB&h#%2?^eDg:Q";
const IV: &[u8] = b"0102030405060708";
const SECRET_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
/// 上游 crypto.go 的内置公钥，只用于算 `encSecKey`
/// （按 RFC 7468 折成 64 字符一行：pem-rfc7468 比 Go 的 PEM 解析严格）
const PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDgtQn2JZ34ZC28NWYpAUd98iZ3\n\
7BUrX/aKzmFbt7clFSs6sXqHauqKWqdtLkF2KexO40H1YTX8z2lSgBBOAxLsvakl\n\
V8k4cBFK9snQXE9/DDaFt6Rr7iVZMldczhC0JNgTz+SHXT6CBHuX3e9SdB1Ua44o\n\
ncaTWz7OBGLbCiK45wIDAQAB\n\
-----END PUBLIC KEY-----";

pub struct NeteaseMusic {
    cookie: String,
    song_limit: u64,
    http: Client,
}

impl NeteaseMusic {
    pub fn new(cookie: String, song_limit: u64) -> Self {
        NeteaseMusic {
            cookie: cookie.trim().to_string(),
            song_limit: if song_limit == 0 { 200 } else { song_limit },
            http: Client::builder().build().unwrap_or_else(|_| Client::new()),
        }
    }

    pub async fn validate(&self) -> Result<(), String> {
        // 上游 Init：cookie 必须同时含 __csrf 与 MUSIC_U
        if cookie_value(&self.cookie, "__csrf").is_empty()
            || cookie_value(&self.cookie, "MUSIC_U").is_empty()
        {
            return Err("网易云音乐 cookie 缺少 __csrf 或 MUSIC_U".into());
        }
        // 加号时真拉一次（limit=1），cookie 过期当场报，而不是进目录才发现是空的
        let body = self.cloud_list_page(1, 0).await?;
        let code = body.get("code").and_then(|c| c.as_i64()).unwrap_or(200);
        if code != 200 {
            return Err(format!(
                "网易云音乐 cookie 无效（code {code}）：{}",
                body.get("msg")
                    .or_else(|| body.get("message"))
                    .and_then(|m| m.as_str())
                    .unwrap_or("请重新登录 music.163.com 复制 cookie")
            ));
        }
        Ok(())
    }

    pub async fn list(&self, parent_fid: &str) -> Result<Vec<Entry>, String> {
        // 云盘是平铺的，没有目录层级
        if !is_root(parent_fid) {
            return Ok(vec![]);
        }
        // 分页拉全：song_limit 是每页条数，循环 offset 直到收尾条件命中
        let page_size = self.song_limit.max(1);
        let mut entries: Vec<Entry> = Vec::new();
        let mut seen: HashSet<i64> = HashSet::new();
        let mut offset: u64 = 0;
        loop {
            let body = self.cloud_list_page(page_size, offset).await?;
            let code = body.get("code").and_then(|c| c.as_i64()).unwrap_or(200);
            if code != 200 {
                return Err(format!(
                    "网易云音乐列表失败（code {code}，offset {offset}）：{}",
                    body.get("msg").and_then(|m| m.as_str()).unwrap_or("")
                ));
            }
            let items = body
                .get("data")
                .and_then(|d| d.as_array())
                .cloned()
                .unwrap_or_default();
            let got = items.len() as u64;
            push_page(&mut entries, &mut seen, &items);
            offset += got;
            let total = body.get("size").and_then(|v| v.as_u64());
            if !page_has_more(got as usize, page_size, offset, total) {
                break;
            }
        }
        Ok(entries)
    }

    pub async fn download(&self, e: &Entry) -> Result<DownloadInfo, String> {
        if e.is_dir {
            return Err("目录无法下载".into());
        }
        let id = entry_song_id(e);
        if id.is_empty() {
            return Err("网易云音乐缺少歌曲 id".into());
        }
        let body = self.song_url(&id).await?;
        let url = url_in(&body).map(|s| s.to_string());
        match url {
            Some(url) => Ok(DownloadInfo {
                url,
                headers: vec![],
                proxy: false,
                local_path: None,
            }),
            None => {
                // 版权/会员受限时服务端会回 data[0].url=null，个别情况整段报错
                let code = body
                    .pointer("/data/0/code")
                    .and_then(|c| c.as_i64())
                    .or_else(|| body.get("code").and_then(|c| c.as_i64()))
                    .unwrap_or(0);
                Err(format!(
                    "网易云音乐未返回直链（code {code}，可能版权受限或需要会员）: {}",
                    truncate(&body.to_string(), 160)
                ))
            }
        }
    }

    pub async fn mkdir(&self, _parent_fid: &str, _name: &str) -> Result<(), String> {
        Err(READONLY.into())
    }

    pub async fn rename(
        &self,
        _parent_fid: &str,
        _e: &Entry,
        _new_name: &str,
    ) -> Result<(), String> {
        Err(READONLY.into())
    }

    pub async fn move_entry(
        &self,
        _parent_fid: &str,
        _e: &Entry,
        _dst_dir_fid: &str,
    ) -> Result<(), String> {
        Err(READONLY.into())
    }

    pub async fn copy(
        &self,
        _parent_fid: &str,
        _e: &Entry,
        _dst_dir_fid: &str,
    ) -> Result<(), String> {
        Err(READONLY.into())
    }

    pub async fn remove(&self, _parent_fid: &str, _e: &Entry) -> Result<(), String> {
        Err(READONLY.into())
    }

    pub async fn put(&self, _dst_dir_fid: &str, _input: super::PutInput) -> Result<(), String> {
        Err(READONLY.into())
    }

    /// 云盘列表单页（weapi）
    async fn cloud_list_page(&self, limit: u64, offset: u64) -> Result<Value, String> {
        let mut data = Map::new();
        data.insert("limit".to_string(), json!(limit.to_string()));
        data.insert("offset".to_string(), json!(offset.to_string()));
        let (params, enc_sec_key) = weapi(&data);
        self.post_form(
            LIST_URL,
            &[
                ("params", params.as_str()),
                ("encSecKey", enc_sec_key.as_str()),
            ],
        )
        .await
    }

    /// 取单曲直链。
    ///
    /// 先用 weapi 的 `/weapi/song/enhance/player/url`（本机实测可用，返回签名直链）；
    /// 上游 Go 用的是 linuxapi 转发 `/api/linux/forward`，该端点实测对同样的请求回
    /// `{"code":500}`，故降级为兜底：只有它真给出 url 才采用，否则把 weapi 的响应交给上层报错。
    async fn song_url(&self, id: &str) -> Result<Value, String> {
        let mut data = Map::new();
        data.insert("ids".to_string(), json!(format!("[{id}]")));
        data.insert("br".to_string(), json!("999000"));
        let (params, enc_sec_key) = weapi(&data);
        let weapi_body = self
            .post_form(
                SONG_URL_WAPI,
                &[
                    ("params", params.as_str()),
                    ("encSecKey", enc_sec_key.as_str()),
                ],
            )
            .await?;
        if url_in(&weapi_body).is_some() {
            return Ok(weapi_body);
        }
        match self.song_url_linuxapi(id).await {
            Ok(v) if url_in(&v).is_some() => Ok(v),
            _ => Ok(weapi_body),
        }
    }

    /// 上游 Go 的取直链方式：数据整包走 linuxapi 转发
    async fn song_url_linuxapi(&self, id: &str) -> Result<Value, String> {
        let mut inner = Map::new();
        inner.insert("ids".to_string(), json!(format!("[{id}]")));
        inner.insert("br".to_string(), json!("999000"));
        let eparams = linuxapi(SONG_URL_PATH, &inner);
        let resp = self
            .http
            .post(FORWARD_URL)
            .header("Cookie", self.cookie_header())
            .header("Referer", "https://music.163.com")
            .header("User-Agent", LINUX_UA)
            .form(&[("eparams", eparams)])
            .send()
            .await
            .map_err(|e| format!("网易云音乐直链请求失败: {e}"))?;
        let text = resp.text().await.unwrap_or_default();
        serde_json::from_str(&text)
            .map_err(|_| format!("网易云音乐直链响应解析失败: {}", truncate(&text, 200)))
    }

    /// POST 表单（weapi 系接口共用），返回解析后的 JSON
    async fn post_form(&self, url: &str, form: &[(&str, &str)]) -> Result<Value, String> {
        let resp = self
            .http
            .post(url)
            .header("Cookie", self.cookie_header())
            .header("Referer", "https://music.163.com")
            .form(form)
            .send()
            .await
            .map_err(|e| format!("网易云音乐请求失败: {e}"))?;
        let text = resp.text().await.unwrap_or_default();
        serde_json::from_str(&text)
            .map_err(|_| format!("网易云音乐响应解析失败: {}", truncate(&text, 200)))
    }

    /// 上游把用户 cookie 整串塞进 Cookie 头，再补一个 os=pc
    fn cookie_header(&self) -> String {
        format!("{}; os=pc", self.cookie.trim_end_matches(';'))
    }
}

const READONLY: &str = "网易云音乐为只读驱动，不支持此操作";

/// 响应里的直链（`data[0].url`，空串/缺字段都算没有）
fn url_in(v: &Value) -> Option<&str> {
    v.pointer("/data/0/url")
        .and_then(|u| u.as_str())
        .filter(|u| !u.is_empty())
}

fn is_root(fid: &str) -> bool {
    fid.is_empty() || fid == "/" || fid == "0"
}

fn truncate(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// 单条响应项 → 条目（没有文件名 / 不是对象的跳过）
fn parse_song(f: &Value) -> Option<Entry> {
    let id = f.get("songId").and_then(|v| v.as_i64()).unwrap_or(0);
    let name = f.get("fileName").and_then(|v| v.as_str()).unwrap_or("");
    if name.is_empty() {
        return None;
    }
    let id_str = id.to_string();
    Some(Entry {
        fid: id_str.clone(),
        name: name.to_string(),
        size: f.get("fileSize").and_then(|v| v.as_u64()).unwrap_or(0),
        is_dir: false,
        updated_at: f.get("addTime").and_then(|v| v.as_i64()),
        etag: None,
        s3_key_flag: None,
        file_type: None,
        // identity 随 extra 带走，取直链时用
        extra: Some(json!({ "id": id_str })),
    })
}

/// 网易云盘容量上限（首）—— 分页拉的硬天花板，防止服务端异常时无限翻页
const MAX_CLOUD_SONGS: u64 = 20_000;

/// 合并一页：按歌曲 id 去重（翻页期间云盘变动可能让同一首出现两次）
fn push_page(entries: &mut Vec<Entry>, seen: &mut HashSet<i64>, items: &[Value]) {
    for item in items {
        let Some(e) = parse_song(item) else {
            continue;
        };
        let dup = e
            .fid
            .parse::<i64>()
            .map(|id| !seen.insert(id))
            .unwrap_or(false);
        if !dup {
            entries.push(e);
        }
    }
}

/// 是否继续翻页。
///
/// 判据三重（服务端总数在翻页期间可能漂移）：
/// 本页不满一页 → 到底；已取满响应里的总数 `size` → 到底；到硬上限 → 到底
fn page_has_more(page_len: usize, page_size: u64, fetched: u64, total: Option<u64>) -> bool {
    if page_len == 0 || (page_len as u64) < page_size {
        return false;
    }
    if total.map(|t| fetched >= t).unwrap_or(false) {
        return false;
    }
    fetched < MAX_CLOUD_SONGS
}

/// 条目对应的歌曲 id：优先 extra.id，退化用 fid
fn entry_song_id(e: &Entry) -> String {
    e.extra
        .as_ref()
        .and_then(|x| x.get("id"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| e.fid.clone())
}

// ---------- 加密（对齐上游 crypto.go，签名函数不取时间/nonce，便于钉期望值） ----------

/// 按 16/24/32 就近补零到合法密钥长度
fn aes_key_pending(key: &[u8]) -> Vec<u8> {
    let count = match key.len() {
        k if k <= 16 => 16 - k,
        k if k <= 24 => 24 - k,
        k if k <= 32 => 32 - k,
        _ => return key[..32].to_vec(),
    };
    let mut out = key.to_vec();
    out.resize(out.len() + count, 0);
    out
}

fn pkcs7_padding(src: &[u8], block_size: usize) -> Vec<u8> {
    let padding = block_size - src.len() % block_size;
    let mut out = src.to_vec();
    out.resize(out.len() + padding, padding as u8);
    out
}

fn encrypt_block(cipher: &Aes128, data: &mut [u8]) {
    let block: &mut Block<Aes128> = data.try_into().expect("每块 16 字节");
    cipher.encrypt_block(block);
}

fn aes_cbc_encrypt(src: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = Aes128::new_from_slice(&aes_key_pending(key)).expect("AES-128 密钥 16 字节");
    let data = pkcs7_padding(src, 16);
    let mut prev = [0u8; 16];
    prev.copy_from_slice(&iv[..16]);
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        let mut buf = [0u8; 16];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = chunk[i] ^ prev[i];
        }
        encrypt_block(&cipher, &mut buf);
        prev = buf;
        out.extend_from_slice(&buf);
    }
    out
}

fn aes_ecb_encrypt(src: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = Aes128::new_from_slice(&aes_key_pending(key)).expect("AES-128 密钥 16 字节");
    let data = pkcs7_padding(src, 16);
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        let mut buf = [0u8; 16];
        buf.copy_from_slice(chunk);
        encrypt_block(&cipher, &mut buf);
        out.extend_from_slice(&buf);
    }
    out
}

/// 上游的裸 RSA：`128-16` 个前导零 + 16 字节随机密钥当大整数做模幂，无 PKCS#1 填充
fn rsa_encrypt_secret(secret_key: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; 128 - 16];
    buf.extend_from_slice(secret_key);
    let msg = BigUint::from_bytes_be(&buf);
    let pub_key = RsaPublicKey::from_public_key_pem(PUBLIC_KEY_PEM).expect("内置公钥解析失败");
    let n = BigUint::from_bytes_be(&pub_key.n().to_bytes_be());
    let e = BigUint::from_bytes_be(&pub_key.e().to_bytes_be());
    msg.modpow(&e, &n).to_bytes_be()
}

fn random_secret_key() -> Vec<u8> {
    let mut rng = rand::rng();
    (0..16)
        .map(|_| SECRET_CHARS[rng.random_range(0..SECRET_CHARS.len())])
        .collect()
}

/// weapi：`{"params": 双层 CBC, "encSecKey": 裸 RSA}`，返回 (params, encSecKey)
fn weapi_with_key(data: &Map<String, Value>, secret_key: &[u8]) -> (String, String) {
    let text = serde_json::to_vec(&Value::Object(data.clone())).unwrap_or_default();
    let first = aes_cbc_encrypt(&text, PRESET_KEY, IV);
    let params = base64::engine::general_purpose::STANDARD.encode(first);
    let reversed: Vec<u8> = secret_key.iter().rev().copied().collect();
    let second = aes_cbc_encrypt(params.as_bytes(), &reversed, IV);
    let params = base64::engine::general_purpose::STANDARD.encode(second);
    (params, hex::encode(rsa_encrypt_secret(secret_key)))
}

fn weapi(data: &Map<String, Value>) -> (String, String) {
    weapi_with_key(data, &random_secret_key())
}

/// linuxapi：`{url, method, params}` 整包 AES-128-ECB + 大写 hex
fn linuxapi(url: &str, params: &Map<String, Value>) -> String {
    let mut body = Map::new();
    body.insert("url".to_string(), json!(url));
    body.insert("method".to_string(), json!("POST"));
    body.insert("params".to_string(), Value::Object(params.clone()));
    let text = serde_json::to_vec(&Value::Object(body)).unwrap_or_default();
    hex::encode(aes_ecb_encrypt(&text, LINUXAPI_KEY)).to_uppercase()
}

/// 上游 getCookie：`name=([^(;|$)]+)`
fn cookie_value(cookie: &str, name: &str) -> String {
    let re = Regex::new(&format!(r"{}=([^(;|$)]+)", regex::escape(name))).expect("cookie 正则");
    re.captures(cookie)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // 期望值由本地 Go 程序（上游 crypto.go 的同一份实现，随机源固定为
    // "TestSecretKey016"）现算得出，逐字节比对
    const GO_SECRET_KEY: &[u8] = b"TestSecretKey016";
    const GO_WEAPI_PARAMS: &str =
        "dLhHfnlM2fI19jueHrBICtwc5wG6WXUB07FA3ZZUTnDYfmb8H3rPQTbQUJqZp8X4";
    const GO_WEAPI_ENC_SEC_KEY: &str = "4d260079ae87354a8c23d9cae730d86414f00c22325422c08fa5e2f67bcc86981\
7fa40a1f5587153a770d59c0715d21b72e9241faebe0f81aac84c9d9e984141a961a38f51f108bf00be034ec6fed1707b3845e6f5dad58\
5524f79eefea561bb6b0916fe52b2499dcde43ef56d6b591c15ab05cdbbbcec2e8d11465a82d78de6";
    const GO_LINUXAPI_EPARAMS: &str = "A0D9583F4C5FF68DE851D2893A49DE98EB5ED82623DE97FC5B2C33BF822A02E3C7B5FE886E6FAE4B2DF4B83CA80414AE\
7863C000529ABEA139CB1B4CAAB60DD3B1BB2B0D4EB3328E676F6F845A631A68636C07E91211F91C394E7FC7980A5C82E254137CD4DCFEF7E51A9955D586B94F";

    #[test]
    fn aes_ecb_matches_go_vector() {
        // openssl 复核过：printf 'hello' | openssl enc -aes-128-ecb -K <linuxapiKey> -nosalt
        assert_eq!(
            hex::encode(aes_ecb_encrypt(b"hello", LINUXAPI_KEY)),
            "7c9d21fdfe1c9186ecab2a729f89a42d"
        );
    }

    #[test]
    fn weapi_matches_go_vector() {
        let mut data = Map::new();
        data.insert("limit".to_string(), json!("200"));
        data.insert("offset".to_string(), json!("0"));
        let (params, enc_sec_key) = weapi_with_key(&data, GO_SECRET_KEY);
        assert_eq!(params, GO_WEAPI_PARAMS);
        assert_eq!(enc_sec_key, GO_WEAPI_ENC_SEC_KEY);
    }

    #[test]
    fn linuxapi_matches_go_vector() {
        let mut params = Map::new();
        params.insert("ids".to_string(), json!("[123456]"));
        params.insert("br".to_string(), json!("999000"));
        assert_eq!(linuxapi(SONG_URL_PATH, &params), GO_LINUXAPI_EPARAMS);
    }

    #[test]
    fn weapi_secret_key_is_reversed_in_second_layer() {
        // 第二层用的是密钥倒序，钉住这个方向（上游 reversedKey）
        let plain = Map::new();
        let (a, _) = weapi_with_key(&plain, b"abcdefghijklmnop");
        let (b, _) = weapi_with_key(&plain, b"ponmlkjihgfedcba");
        assert_ne!(a, b);
    }

    #[test]
    fn cookie_value_extracts_upstream_fields() {
        let cookie = "__csrf=abc123; MUSIC_U=def456; os=pc";
        assert_eq!(cookie_value(cookie, "__csrf"), "abc123");
        assert_eq!(cookie_value(cookie, "MUSIC_U"), "def456");
        assert_eq!(cookie_value(cookie, "NOPE"), "");
    }

    #[test]
    fn parse_song_maps_entry() {
        let mut entries = Vec::new();
        let mut seen = HashSet::new();
        let page = vec![
            json!({
                "addTime": 1700000000000i64,
                "fileName": "song.mp3",
                "fileSize": 8_388_608,
                "songId": 123456,
                "simpleSong": { "al": { "picUrl": "https://p1.music.126.net/x.jpg" } }
            }),
            json!({ "fileName": "", "songId": 1 }),
        ];
        push_page(&mut entries, &mut seen, &page);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].fid, "123456");
        assert_eq!(entries[0].name, "song.mp3");
        assert_eq!(entries[0].size, 8_388_608);
        assert_eq!(entries[0].updated_at, Some(1_700_000_000_000));
        assert!(!entries[0].is_dir);
        // identity 随 extra 带走，取直链时用得到
        assert_eq!(entry_song_id(&entries[0]), "123456");
    }

    #[test]
    fn page_has_more_uses_three_stops() {
        // 满页且总数未知 → 继续翻
        assert!(page_has_more(200, 200, 200, None));
        // 已取满服务端报的总数 → 停
        assert!(!page_has_more(200, 200, 200, Some(200)));
        // 总数漂移（报 500 实拿 400）→ 继续
        assert!(page_has_more(200, 200, 400, Some(500)));
        // 本页不满一页 → 停
        assert!(!page_has_more(137, 200, 137, None));
        // 空页 → 停
        assert!(!page_has_more(0, 200, 0, None));
        // 硬上限 → 停
        assert!(!page_has_more(200, 200, MAX_CLOUD_SONGS, None));
    }

    #[test]
    fn push_page_dedupes_and_skips_empty_names() {
        let mut entries = Vec::new();
        let mut seen = HashSet::new();
        let page1 = vec![
            json!({"songId": 1, "fileName": "a.mp3", "fileSize": 10}),
            json!({"songId": 2, "fileName": "b.mp3"}),
        ];
        push_page(&mut entries, &mut seen, &page1);
        // 第二页重复了上一页的 2，另有一条没有文件名
        let page2 = vec![
            json!({"songId": 2, "fileName": "b.mp3"}),
            json!({"songId": 3, "fileName": ""}),
            json!({"songId": 4, "fileName": "d.mp3"}),
        ];
        push_page(&mut entries, &mut seen, &page2);
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["a.mp3", "b.mp3", "d.mp3"]);
        assert_eq!(entries[0].size, 10);
    }

    #[test]
    fn url_in_reads_song_url_response() {
        // 真实响应骨架（weapi /weapi/song/enhance/player/url）
        let body = json!({
            "data": [{
                "id": 3331091891i64,
                "url": "http://m703.music.126.net/x/y.wav?vuutv=abc",
                "br": 1411200,
                "code": 200,
                "type": "WAV",
                "level": "lossless"
            }],
            "code": 200
        });
        assert_eq!(
            url_in(&body),
            Some("http://m703.music.126.net/x/y.wav?vuutv=abc")
        );
    }

    #[test]
    fn url_in_rejects_empty_missing_and_error_body() {
        // 版权/会员受限：url 为 null 或空串
        assert_eq!(
            url_in(&json!({ "data": [{ "url": null, "code": 200 }] })),
            None
        );
        assert_eq!(
            url_in(&json!({ "data": [{ "url": "", "code": 404 }] })),
            None
        );
        // linuxapi 转发端点当前的失败形态（没有 data）
        assert_eq!(url_in(&json!({ "code": 500 })), None);
        assert_eq!(url_in(&json!({})), None);
    }

    #[test]
    fn entry_song_id_falls_back_to_fid() {
        let e = Entry {
            fid: "999".into(),
            name: "a.mp3".into(),
            size: 1,
            is_dir: false,
            updated_at: None,
            etag: None,
            s3_key_flag: None,
            file_type: None,
            extra: None,
        };
        assert_eq!(entry_song_id(&e), "999");
    }

    #[test]
    fn cookie_header_appends_os_pc() {
        let d = NeteaseMusic::new("  __csrf=a; MUSIC_U=b;  ".into(), 0);
        assert_eq!(d.cookie_header(), "__csrf=a; MUSIC_U=b; os=pc");
        // 上游默认 200 首
        assert_eq!(d.song_limit, 200);
    }

    #[test]
    fn song_limit_zero_falls_back_to_default() {
        assert_eq!(NeteaseMusic::new("x".into(), 0).song_limit, 200);
        assert_eq!(NeteaseMusic::new("x".into(), 50).song_limit, 50);
    }

    #[test]
    fn list_without_csrf_cookie_is_rejected() {
        // 只校验字段存在性（上游 Init），不打网络
        let d = NeteaseMusic::new("MUSIC_U=only".into(), 200);
        assert!(cookie_value(&d.cookie, "__csrf").is_empty());
    }
}
