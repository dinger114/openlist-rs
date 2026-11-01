//! OpenList 式静态 API 令牌（对齐 Go 版 `setting` 表里的 `token`）。
//!
//! 与面板会话 token（`state::issue_session`，7 天 TTL、重启即失效）的区别：
//! 令牌持久化在加密数据库里，永不过期，供 ostrm / AList 协议客户端 / WebDAV
//! 直接以 `Authorization: <token>` 调用 API —— 这类客户端只存一次凭据，没法
//! 跟着会话续期。
//!
//! 校验语义对齐 Go 版 `middlewares.Auth`：常量时间比较，且**空值一律不通过**。
//! 后者是必修的防御：Go 版的 `ConstantTimeCompare("", "")` 返回 1，且这段判断
//! 在「无 token 走 guest」分支之前，一旦把令牌清空，任何匿名请求都会被当成管理员
//! （见 OpenList `server/middlewares/auth.go:20`）。

use crate::sign::constant_time_eq;

/// 前缀与 Go 版一致（`pkg/utils/random.Token`：`openlist-` + uuid + 64 位随机）
const PREFIX: &str = "openlist-";

/// 生成新令牌：`openlist-<uuid>-<64 hex>`。
///
/// 长度与熵对齐 Go 版（uuid 122 bit + 256 bit 随机），肉眼可分块便于抄写。
pub(crate) fn generate() -> String {
    use rand::RngExt;
    let mut raw = [0u8; 32];
    rand::rng().fill(&mut raw);
    format!("{PREFIX}{}-{}", uuid::Uuid::new_v4(), hex::encode(raw))
}

/// 常量时间比较。空值（任一侧）直接判否 —— 见文件头注释。
pub(crate) fn matches(expected: &str, presented: &str) -> bool {
    if expected.is_empty() || presented.is_empty() {
        return false;
    }
    constant_time_eq(expected.as_bytes(), presented.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_token_has_prefix_and_enough_entropy() {
        let t = generate();
        assert!(t.starts_with("openlist-"), "前缀不对: {t}");
        // openlist- + 36(uuid) + '-' + 64(hex) = 110
        assert_eq!(t.len(), PREFIX.len() + 36 + 1 + 64, "长度不对: {t}");
        assert!(t.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
        assert_ne!(t, generate(), "两次生成不应相同");
    }

    #[test]
    fn matches_only_on_exact_equal_nonempty() {
        let t = generate();
        assert!(matches(&t, &t));
        assert!(!matches(&t, &format!("{t}x")));
        assert!(!matches(&t, ""));
        assert!(!matches("", &t));
    }

    /// 空令牌绝不能放行：否则空 Authorization 会被判成管理员（Go 版的坑）
    #[test]
    fn empty_token_never_matches() {
        assert!(!matches("", ""));
        assert!(!matches("", "openlist-x"));
    }
}
