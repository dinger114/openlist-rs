//! 面板密码哈希与校验（argon2id，PHC 串落库）
//!
//! 早期版本把面板密码**明文**存在加密库里、登录时直接 `==` 比较，两个登录端点
//! （面板 `/api/login`、协议 `/api/auth/login`）都是如此。现在库里存 PHC 串
//! （`$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>`）；老库里还是明文时，
//! **首次成功登录会透明升级**为哈希，用户不需要改密码。
//!
//! 参数用 argon2id 官方默认（m=19MiB、t=2、p=1、32 字节输出）：一次约 20~100ms、
//! 瞬时占 19MiB 内存。因此调用方必须
//!   ① 放进 `tokio::task::spawn_blocking`（别堵 async worker —— argon2 是同步 CPU 计算），
//!   ② 限制并发（`AppState::password_gate`，同时最多 2 个），
//! 否则登录洪水能用 19MiB/请求把内存打满。
use argon2::{
    password_hash::{
        phc::{ParamsString, PasswordHash},
        PasswordHasher, PasswordVerifier,
    },
    Argon2, Params,
};

/// 库里存的是不是 PHC 串（用于判断是否需要透明升级）
pub(crate) fn is_hashed(stored: &str) -> bool {
    stored.starts_with("$argon2")
}

/// 生成 PHC 哈希串（同步、CPU/内存密集 —— 调用方负责 spawn_blocking + 限并发）
pub(crate) fn hash_password(plain: &str) -> Result<String, String> {
    Argon2::default()
        .hash_password(plain.as_bytes())
        .map(|h| h.to_string())
        .map_err(|e| format!("密码哈希失败: {e}"))
}

/// 校验结果
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct VerifyOutcome {
    pub(crate) ok: bool,
    /// 密码正确但库里是旧格式（明文）或旧参数 → 调用方应回写新哈希
    pub(crate) needs_rehash: bool,
}

/// 校验密码：PHC 串走 argon2 verify；明文（老库）走定长比较并标记需要升级
pub(crate) fn verify_password(stored: &str, plain: &str) -> VerifyOutcome {
    // 空口令永不通过：明文路径下 constant_time_eq("","") 会返回 true，于是「库里密码为
    // 空」就成了「空密码可登录」的后门。init_web_auth 会兜底生成随机密码，但不留这口子。
    if plain.is_empty() || stored.is_empty() {
        return VerifyOutcome {
            ok: false,
            needs_rehash: false,
        };
    }
    if is_hashed(stored) {
        return match Argon2::default().verify_password(plain.as_bytes(), stored) {
            Ok(()) => VerifyOutcome {
                ok: true,
                needs_rehash: params_outdated(stored),
            },
            Err(_) => VerifyOutcome {
                ok: false,
                needs_rehash: false,
            },
        };
    }
    // 老库明文：定长比较（别用 == 短路比较，顺手把长度差异也抹平）
    let ok = crate::sign::constant_time_eq(stored.as_bytes(), plain.as_bytes());
    VerifyOutcome {
        ok,
        needs_rehash: ok,
    }
}

/// 哈希串里的参数是否已不是当前默认（将来调参数时，登录顺手重算）
fn params_outdated(stored: &str) -> bool {
    let Ok(ph) = PasswordHash::new(stored) else {
        return true;
    };
    match ParamsString::try_from(&Params::default()) {
        Ok(expected) => ph.params != expected,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_argon2id_phc_with_default_params() {
        let h = hash_password("s3cret-密码").unwrap();
        assert!(
            h.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"),
            "PHC 串与默认参数不符: {h}"
        );
        assert!(is_hashed(&h));
        assert!(!params_outdated(&h), "新建的哈希不该被判为参数过期");
    }

    #[test]
    fn verify_roundtrip_and_wrong_password() {
        let h = hash_password("s3cret-密码").unwrap();
        assert_eq!(
            verify_password(&h, "s3cret-密码"),
            VerifyOutcome {
                ok: true,
                needs_rehash: false
            }
        );
        assert!(!verify_password(&h, "s3cret-密码 ").ok);
        assert!(!verify_password(&h, "").ok);
        assert!(!verify_password(&h, "S3CRET-密码").ok);
    }

    /// 同一密码两次哈希必须不同（盐随机）
    #[test]
    fn salt_is_random_per_hash() {
        assert_ne!(
            hash_password("same").unwrap(),
            hash_password("same").unwrap()
        );
    }

    /// 老库明文：比对成功且标记升级；失败**不**标记（别把错密码写成哈希）
    #[test]
    fn legacy_plaintext_marks_rehash_only_on_success() {
        assert_eq!(
            verify_password("old-plain", "old-plain"),
            VerifyOutcome {
                ok: true,
                needs_rehash: true
            }
        );
        assert_eq!(
            verify_password("old-plain", "nope"),
            VerifyOutcome {
                ok: false,
                needs_rehash: false
            }
        );
    }

    /// 空串、损坏的哈希串都必须是「不通过」而不是 panic
    #[test]
    fn empty_and_broken_inputs_are_rejected() {
        assert!(!is_hashed(""));
        assert!(!verify_password("", "").ok);
        assert!(!verify_password("$argon2id$garbage", "x").ok);
        assert!(
            params_outdated("$argon2id$garbage"),
            "解析不了的串按过期处理"
        );
    }
}
