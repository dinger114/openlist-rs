//! 日期时间工具：Howard Hinnant 的 civil calendar 算法集中实现。
//!
//! 此前 `days_from_civil` / `civil_from_days` 被手抄进 13 个驱动文件（15 处调用点），
//! 副本之间存在细微差异（有的用 `div_euclid`、有的用 C 截断除法模拟 floor），
//! 而只有 webdav 一份带测试。集中到此处并配边界测试，避免"改了副本 A 忘了副本 B"。

/// 自 1970-01-01 起的天数 -> (年, 月, 日)。
///
/// 用 `div_euclid` / `rem_euclid`，负数天数（1970 年之前）同样正确，
/// 不需要 C 版那种 `z - 146096` 截断补偿写法。
pub(crate) fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as u32, d as u32)
}

/// (年, 月, 日) -> 自 1970-01-01 起的天数。
///
/// 参数取 i64：调用方多从字符串解析出 i64，少数持有 u32 的调用点显式 `as i64`，
/// 好处是不同驱动不需要各自维护一份签名。
pub(crate) fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// 自 1970-01-01 起的天数 -> 三字母星期名（UTC，Sun..Sat 取前三位）。
///
/// 1970-01-01 是周四，故下标 0 = "Thu"。**星期数组必须与下标算法成对**：
/// 曾出现 ilanzou 抄了 `(days + 4) % 7`（配 Sun 起头的数组才对）却配上 Thu 起头的
/// 数组，结果星期名整体错 4 天。集中实现后这类错配不会再发生。
pub(crate) fn weekday_short_utc(days: i64) -> &'static str {
    const W: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    W[days.rem_euclid(7) as usize]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_civil_from_days_epoch_and_before() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        assert_eq!(civil_from_days(-365), (1969, 1, 1));
    }

    #[test]
    fn test_days_from_civil_epoch_and_before() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(1969, 12, 31), -1);
        assert_eq!(days_from_civil(1969, 1, 1), -365);
    }

    /// 世纪闰年规则：能被 400 整除是闰年，能被 100 整除不是（1900 非闰、2000 是闰）
    #[test]
    fn test_leap_year_boundaries() {
        assert_eq!(days_from_civil(2000, 2, 29), 11016);
        assert_eq!(days_from_civil(2024, 2, 29), 19782);
        // 1900-02-28 的下一天是 1900-03-01（1900 不是闰年，没有 02-29）
        assert_eq!(days_from_civil(1900, 2, 28), -25509);
        assert_eq!(days_from_civil(1900, 3, 1), -25508);
        assert_eq!(
            days_from_civil(1900, 3, 1) - days_from_civil(1900, 2, 28),
            1
        );
        // 2100 同样不是闰年
        assert_eq!(
            days_from_civil(2100, 3, 1) - days_from_civil(2100, 2, 28),
            1
        );
        assert_eq!(
            days_from_civil(2000, 3, 1) - days_from_civil(2000, 2, 29),
            1
        );
    }

    #[test]
    fn test_month_and_year_boundaries() {
        assert_eq!(days_from_civil(2024, 1, 31), 19753);
        assert_eq!(days_from_civil(2024, 3, 1), 19783);
        assert_eq!(days_from_civil(2024, 12, 31), 20088);
        // 2024-02-29 的下一天是 2024-03-01
        assert_eq!(
            days_from_civil(2024, 2, 29) + 1,
            days_from_civil(2024, 3, 1)
        );
        assert_eq!(civil_from_days(19783), (2024, 3, 1));
    }

    /// 两个函数互为逆运算：覆盖闰年、月末、1970 前后（含负天数）
    #[test]
    fn test_round_trip() {
        for z in (-100_000i64..100_000).step_by(7) {
            let (y, m, d) = civil_from_days(z);
            assert_eq!(
                days_from_civil(y, m as i64, d as i64),
                z,
                "round trip failed at z={z} -> {y}-{m}-{d}"
            );
        }
        // 逐日覆盖 1970 年前后各 400 天（跨纪元边界）
        for z in -400i64..400 {
            let (y, m, d) = civil_from_days(z);
            assert_eq!(days_from_civil(y, m as i64, d as i64), z);
        }
    }

    /// 1970-01-01 是周四；下标算法与星期数组必须配对
    #[test]
    fn test_weekday_short_utc() {
        let expect = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
        for (i, name) in expect.iter().enumerate() {
            assert_eq!(weekday_short_utc(i as i64), *name);
            assert_eq!(weekday_short_utc(i as i64 + 7), *name);
        }
        // 负天数也要落在数组内（不 panic、不越界）
        assert_eq!(weekday_short_utc(-1), "Wed");
        assert_eq!(weekday_short_utc(-7), "Thu");
    }
}
