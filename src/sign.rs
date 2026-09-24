//! 下载链接签名 —— 与 Go 版 OpenList 的 `pkg/sign/hmac.go` 逐字对齐
//!
//! 格式：
//!   `sign = base64.URLEncoding(HMAC-SHA256(secret, "{data}:{expire}")) + ":" + expire`
//! （Go 用的是 `base64.URLEncoding`，即 **带 `=` 填充** 的 URL-safe base64）
//!
//! `expire` 是 Unix 秒，`0` 表示永不过期。
//! `data` 是规范化后的完整路径，形如 `/账号名/目录/文件`（不带 `/d`、`/p` 前缀）。
//!
//! 为什么是 URL 签名而不是鉴权头：播放器/TVBox 播放视频时带不了 `Authorization` 头，
//! 官方因此把授权信息放进链接本身；`/d` `/p` 两个端点据此校验。
use base64::engine::{general_purpose::URL_SAFE, Engine};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

/// 由数据目录的存储密钥派生签名密钥：`HMAC(store_key, "openlist-rs/sign")`。
///
/// 做域分离，避免把 AES 存储密钥直接当 HMAC 密钥复用同一用途；也不需要新增配置项。
pub(crate) fn sign_secret(store_key: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(store_key).expect("HMAC 接受任意长度密钥");
    mac.update(b"openlist-rs/sign");
    mac.finalize().into_bytes().into()
}

/// 生成签名（`expire` 为 Unix 秒，`0` = 不过期）
pub(crate) fn sign(data: &str, expire: i64, secret: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC 接受任意长度密钥");
    mac.update(format!("{data}:{expire}").as_bytes());
    let sig = URL_SAFE.encode(mac.finalize().into_bytes());
    format!("{sig}:{expire}")
}

/// 校验失败的四种原因（与 Go 版的四个错误变量一一对应）
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SignError {
    ExpireMissing,
    ExpireInvalid,
    SignExpired,
    SignInvalid,
}

impl SignError {
    pub(crate) fn message(&self) -> &'static str {
        match self {
            SignError::ExpireMissing => "sign expire missing",
            SignError::ExpireInvalid => "sign expire invalid",
            SignError::SignExpired => "sign expired",
            SignError::SignInvalid => "sign invalid",
        }
    }
}

/// 校验签名：先取尾部 `:expire` 判过期，再重算比对（与 Go `HMACSign.Verify` 同序）
pub(crate) fn verify(data: &str, signature: &str, secret: &[u8]) -> Result<(), SignError> {
    // Go: exp := sign[strings.LastIndex(sign, ":")+1:]
    // 没有 ':' 时 Go 取整串（随后 ParseInt 失败 → expire invalid）；这里保持一致
    let exp = match signature.rfind(':') {
        Some(i) => &signature[i + 1..],
        None => signature,
    };
    if exp.is_empty() {
        return Err(SignError::ExpireMissing);
    }
    let expires: i64 = exp.parse().map_err(|_| SignError::ExpireInvalid)?;
    if expires != 0 && expires < now_unix() {
        return Err(SignError::SignExpired);
    }
    let expected = sign(data, expires, secret);
    if constant_time_eq(expected.as_bytes(), signature.as_bytes()) {
        Ok(())
    } else {
        Err(SignError::SignInvalid)
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 定长比较：签名是攻击者可控输入，避免按字节短路比较泄漏时序
/// （Go 版是字符串直接比较，这里严格更严）
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"test-secret";

    /// 已知向量：由 **Go 版源码实跑** 生成
    /// （把 OpenList/pkg/sign/{hmac.go,sign.go} 原样拷成 main 包 + 一段打印代码，`go run`）
    /// 任何一处不一致（base64 是否填充、":" 分隔、字段顺序）都会被这几个用例挡住。
    #[test]
    fn known_vectors_match_go_implementation() {
        let cases = [
            (
                "/alice/docs/a.txt",
                0i64,
                "08pei6caWE8_qQXAJ68y-J19qlSeDZqCcciFpD_nUd4=:0",
            ),
            (
                "/账号/目录/中文 文件.mp4",
                0,
                "xMjPnxmkXjhe7wLk1M0P4rM7Sc1bMPLGSNE-D4Z0nPA=:0",
            ),
            (
                "/alice/docs/a.txt",
                4102444800,
                "Mj83SDgoB_X4ZFX4FzKdekThICDYeJF_HRlng0Z4DJk=:4102444800",
            ),
            (
                "/bob/big file.bin",
                4102444800,
                "SYYAB8yfs6FqOMiPuJojDpYc2FxN9BXmxjVzbSRmcsM=:4102444800",
            ),
        ];
        for (data, expire, want) in cases {
            assert_eq!(
                sign(data, expire, SECRET),
                want,
                "签名与 Go 实现不一致: {data}"
            );
        }
    }

    /// 校验结果与 Go 版 `Verify` 的四种错误逐一对齐
    #[test]
    fn verify_matches_go_error_semantics() {
        let v = sign("/alice/docs/a.txt", 0, SECRET);
        assert_eq!(verify("/alice/docs/a.txt", &v, SECRET), Ok(()));
        // 路径被换掉 → 签名无效
        assert_eq!(
            verify("/alice/docs/b.txt", &v, SECRET),
            Err(SignError::SignInvalid)
        );
        // 篡改签名尾部 base64
        let mut bad = v.clone();
        bad.replace_range(..1, "X");
        assert_eq!(
            verify("/alice/docs/a.txt", &bad, SECRET),
            Err(SignError::SignInvalid)
        );
        // 已过期（expire=1）
        let expired = sign("/alice/docs/a.txt", 1, SECRET);
        assert_eq!(
            verify("/alice/docs/a.txt", &expired, SECRET),
            Err(SignError::SignExpired)
        );
        // 尾部不是数字
        let bogus = format!("{}:abc", &v[..v.len() - 2]);
        assert_eq!(
            verify("/alice/docs/a.txt", &bogus, SECRET),
            Err(SignError::ExpireInvalid)
        );
        // 空 expire / 空签名（Go: 都是 expire missing）
        assert_eq!(
            verify("/alice/docs/a.txt", "abc:", SECRET),
            Err(SignError::ExpireMissing)
        );
        assert_eq!(
            verify("/alice/docs/a.txt", "", SECRET),
            Err(SignError::ExpireMissing)
        );
        // 别的密钥签的 → 无效
        assert_eq!(
            verify(
                "/alice/docs/a.txt",
                &sign("/alice/docs/a.txt", 0, b"other"),
                SECRET
            ),
            Err(SignError::SignInvalid)
        );
    }

    /// 未过期（未来时间戳）应通过；expire=0 永不过期
    #[test]
    fn not_yet_expired_is_accepted() {
        let far = 4102444800; // 2100-01-01
        assert_eq!(verify("/x", &sign("/x", far, SECRET), SECRET), Ok(()));
        assert_eq!(verify("/x", &sign("/x", 0, SECRET), SECRET), Ok(()));
    }

    /// 签名密钥派生：稳定、与存储密钥不同、不同存储密钥派生出不同签名密钥
    #[test]
    fn sign_secret_is_derived_and_stable() {
        let k1 = [1u8; 32];
        let k2 = [2u8; 32];
        assert_eq!(sign_secret(&k1), sign_secret(&k1));
        assert_ne!(sign_secret(&k1), sign_secret(&k2));
        assert_ne!(sign_secret(&k1).to_vec(), k1.to_vec());
        // 派生结果与手算 HMAC 一致（换实现也要保持同一密钥）
        assert_eq!(sign_secret(&k1), {
            let mut mac = HmacSha256::new_from_slice(&k1).unwrap();
            mac.update(b"openlist-rs/sign");
            let out: [u8; 32] = mac.finalize().into_bytes().into();
            out
        });
    }
}
