//! 登录失败限速（内存态，重启即清）
//!
//! 规则：
//! - 同一来源 IP 连错 5 次 → 锁 60 秒；锁定之后每再错一次翻倍（上限 15 分钟）；成功登录清零
//! - 全局护栏：60 秒窗口内失败总数超过 50 → 全局暂缓 30 秒（多 IP 分布式猜密码时的最后一道闸）
//!
//! 为什么按 **TCP 对端 IP** 而不是 `X-Forwarded-For`：XFF 是客户端可控的头，
//! 直接拿它做限速键等于让攻击者伪造头绕过限速；只有明确部署在可信反代后面时才该看它。
//! 代价是反代场景下所有客户端共用一个 IP（那时其实是「全局限速」，全局护栏仍有效）。
//!
//! 时间一律由调用方以 `now: Instant` 传入 —— 函数内部取时间就没法写确定性单测。
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// 连错多少次开始锁
const FAIL_THRESHOLD: u32 = 5;
/// 首次锁定时长
const BASE_LOCK: Duration = Duration::from_secs(60);
/// 锁定时长上限
const MAX_LOCK: Duration = Duration::from_secs(15 * 60);
/// 全局护栏的统计窗口
const GLOBAL_WINDOW: Duration = Duration::from_secs(60);
/// 窗口内失败总数超过该值 → 触发全局暂缓
const GLOBAL_MAX_FAILS: usize = 50;
/// 全局暂缓时长
const GLOBAL_PAUSE: Duration = Duration::from_secs(30);
/// 多久没动静就丢弃该 IP 的记录（防 map 无限增长）
const IDLE_TTL: Duration = Duration::from_secs(3600);

#[derive(Default, Clone, Copy)]
struct IpState {
    fails: u32,
    locked_until: Option<Instant>,
    last: Option<Instant>,
}

pub(crate) struct LoginLimiter {
    ips: HashMap<IpAddr, IpState>,
    /// 全局窗口内的失败时刻（滑动窗口，prune 时裁掉窗口外的）
    global_fails: Vec<Instant>,
    global_until: Option<Instant>,
}

impl LoginLimiter {
    pub(crate) fn new() -> Self {
        Self {
            ips: HashMap::new(),
            global_fails: Vec::new(),
            global_until: None,
        }
    }

    /// 当前是否被限速：`Ok` 放行，`Err(剩余时长)` 拒绝
    pub(crate) fn check(&mut self, ip: IpAddr, now: Instant) -> Result<(), Duration> {
        self.prune(now);
        if let Some(until) = self.global_until {
            if until > now {
                return Err(until - now);
            }
        }
        if let Some(until) = self.ips.get(&ip).and_then(|st| st.locked_until) {
            if until > now {
                return Err(until - now);
            }
        }
        Ok(())
    }

    /// 记一次失败（调用方在返回失败响应**之前**调用）
    pub(crate) fn record_failure(&mut self, ip: IpAddr, now: Instant) {
        self.prune(now);
        let st = self.ips.entry(ip).or_default();
        st.fails = st.fails.saturating_add(1);
        st.last = Some(now);
        if st.fails >= FAIL_THRESHOLD {
            // 第 5 次锁 60s，第 6 次 120s，第 7 次 240s……上限 15 分钟
            let over = st.fails - FAIL_THRESHOLD;
            let lock = (BASE_LOCK * 2u32.saturating_pow(over.min(8))).min(MAX_LOCK);
            st.locked_until = Some(now + lock);
        }
        self.global_fails.push(now);
        if self.global_fails.len() > GLOBAL_MAX_FAILS {
            self.global_until = Some(now + GLOBAL_PAUSE);
        }
    }

    /// 成功登录：清掉该 IP 的失败计数与锁定
    pub(crate) fn record_success(&mut self, ip: IpAddr) {
        self.ips.remove(&ip);
    }

    /// 丢掉过期数据：窗口外的全局失败记录、久未活动的 IP 记录
    fn prune(&mut self, now: Instant) {
        let window_start = now.checked_sub(GLOBAL_WINDOW).unwrap_or(now);
        self.global_fails.retain(|t| *t >= window_start);
        if self.global_until.is_some_and(|u| u <= now) {
            self.global_until = None;
        }
        let idle_before = now.checked_sub(IDLE_TTL).unwrap_or(now);
        self.ips.retain(|_, st| {
            let lock_active = st.locked_until.is_some_and(|u| u > now);
            let recent = st.last.is_some_and(|l| l >= idle_before);
            lock_active || recent
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, n))
    }

    /// 前 5 次只是记数（响应仍是 401），第 6 次起被限速；到期后放行；别的 IP 不受影响
    #[test]
    fn locks_after_five_failures_and_expires() {
        let t0 = Instant::now();
        let mut l = LoginLimiter::new();
        for _ in 0..FAIL_THRESHOLD {
            assert!(l.check(ip(1), t0).is_ok());
            l.record_failure(ip(1), t0);
        }
        let left = l.check(ip(1), t0).unwrap_err();
        assert!(
            left <= BASE_LOCK && left > BASE_LOCK - Duration::from_secs(1),
            "{left:?}"
        );
        // 到期后放行
        assert!(l
            .check(ip(1), t0 + BASE_LOCK + Duration::from_secs(1))
            .is_ok());
        // 别的 IP 完全不受影响
        assert!(l.check(ip(2), t0).is_ok());
    }

    /// 锁定期间继续错：锁定时长翻倍，且有上限
    #[test]
    fn lock_doubles_and_is_capped() {
        let t0 = Instant::now();
        let mut l = LoginLimiter::new();
        for _ in 0..FAIL_THRESHOLD {
            l.record_failure(ip(1), t0);
        }
        assert_eq!(l.check(ip(1), t0).unwrap_err(), BASE_LOCK);
        l.record_failure(ip(1), t0); // 第 6 次
        assert_eq!(l.check(ip(1), t0).unwrap_err(), BASE_LOCK * 2);
        for _ in 0..20 {
            l.record_failure(ip(1), t0);
        }
        assert_eq!(
            l.check(ip(1), t0).unwrap_err(),
            MAX_LOCK,
            "锁定时长必须有上限"
        );
    }

    /// 成功登录清零该 IP
    #[test]
    fn success_clears_the_ip() {
        let t0 = Instant::now();
        let mut l = LoginLimiter::new();
        for _ in 0..FAIL_THRESHOLD {
            l.record_failure(ip(1), t0);
        }
        assert!(l.check(ip(1), t0).is_err());
        l.record_success(ip(1));
        assert!(l.check(ip(1), t0).is_ok());
        // 清零后要重新攒满 5 次才会再锁
        for _ in 0..FAIL_THRESHOLD - 1 {
            l.record_failure(ip(1), t0);
        }
        assert!(l.check(ip(1), t0).is_ok());
    }

    /// 全局护栏：多 IP 分布式猜密码时全线暂缓，过后自动恢复
    #[test]
    fn global_guard_pauses_everything_then_recovers() {
        let t0 = Instant::now();
        let mut l = LoginLimiter::new();
        for i in 0..=GLOBAL_MAX_FAILS {
            l.record_failure(ip(i as u8 + 1), t0);
        }
        assert!(l.check(ip(200), t0).is_err(), "全局护栏应拦下全新 IP");
        assert!(l
            .check(ip(200), t0 + GLOBAL_PAUSE + Duration::from_secs(1))
            .is_ok());
    }

    /// 久未活动的 IP 记录会被丢掉（不会无限增长）
    #[test]
    fn stale_ip_records_are_dropped() {
        let t0 = Instant::now();
        let mut l = LoginLimiter::new();
        for i in 0..10 {
            l.record_failure(ip(i as u8 + 1), t0);
        }
        assert_eq!(l.ips.len(), 10);
        // 一小时后再来一次，旧记录应被清掉
        // 触发一次 prune：空闲记录被丢弃，该 IP 重新从 0 计数（仍放行）
        assert!(l
            .check(ip(99), t0 + IDLE_TTL + Duration::from_secs(1))
            .is_ok());
        assert_eq!(l.ips.len(), 0, "空闲超时的 IP 记录必须被回收");
    }
}
