//! 进程内滑动窗口限速：登录失败与注册共用同一套实现。
//!
//! **取舍：状态只在内存里，重启清零。** 本服务是单实例自托管，进程内计数足以挡住
//! 脚本化的口令爆破与批量注册；落库会给认证/注册路径增加写事务与 schema 迁移，
//! 而真正需要跨重启、跨实例的限速应该放在反向代理或 WAF 上。代价是重启后计数归零，
//! 这是可接受的：爆破者不知道重启时机，运维重启也不会让已泄露的口令重新可用。
//!
//! 键由调用方决定（登录用小写用户名，注册用来源地址）。窗口与上限分开传入：
//! 窗口固定在构造时（登录 5 分钟、注册 1 小时），上限来自 `[accounts]` 配置，
//! `0` 表示不限制。

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// 登录失败窗口：5 分钟。
pub(crate) const LOGIN_WINDOW: Duration = Duration::from_secs(5 * 60);

/// 注册窗口：1 小时。
pub(crate) const REGISTRATION_WINDOW: Duration = Duration::from_secs(60 * 60);

/// 键数量上限：超过后顺手清理全部过期键，避免被大量随机用户名/伪造 IP 撑大内存。
const MAX_KEYS: usize = 4096;

/// 按 key 计数的滑动窗口。
///
/// 每个 key 只保留窗口内的记录，因此「窗口滑过」后自动失效，不需要后台任务。
#[derive(Debug)]
pub(crate) struct SlidingWindowLimiter {
    window: Duration,
    entries: Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl SlidingWindowLimiter {
    /// 用给定窗口构造一个空限速器。
    pub(crate) fn new(window: Duration) -> Self {
        Self { window, entries: Mutex::new(HashMap::new()) }
    }

    /// 窗口内该 key 的记录数达到 `limit` 时返回还需等待多久；`limit = 0` 表示不限。
    ///
    /// 返回的等待时间取「最早一条记录滑出窗口」所需的时长——到那时计数会降到
    /// 上限以下，客户端可以重试。没有记录在窗口内时返回 `None`。
    pub(crate) fn blocked_for(&self, key: &str, limit: u64) -> Option<Duration> {
        self.blocked_for_at(key, limit, Instant::now())
    }

    /// 记录一次事件（登录失败、注册成功）。
    pub(crate) fn record(&self, key: &str) {
        self.record_at(key, Instant::now());
    }

    /// 清零该 key 的记录（登录成功、管理员重置口令后调用）。
    pub(crate) fn reset(&self, key: &str) {
        let mut entries = lock(&self.entries);
        entries.remove(key);
    }

    /// [`Self::blocked_for`] 的可注入时间版本；单测用它避免真的等窗口过去。
    fn blocked_for_at(&self, key: &str, limit: u64, now: Instant) -> Option<Duration> {
        if limit == 0 {
            return None;
        }
        let window = self.window;
        let mut entries = lock(&self.entries);
        let oldest = {
            let stamps = entries.get_mut(key)?;
            prune(stamps, now, window);
            let count = u64::try_from(stamps.len()).unwrap_or(u64::MAX);
            if count < limit {
                return None;
            }
            stamps.front().copied()?
        };
        // 最早一条记录滑出窗口时计数才可能低于上限：等待时间 = 窗口 - 已过去的时间。
        Some(window.saturating_sub(now.saturating_duration_since(oldest)))
    }

    /// [`Self::record`] 的可注入时间版本。
    fn record_at(&self, key: &str, now: Instant) {
        let mut entries = lock(&self.entries);
        if entries.len() >= MAX_KEYS && !entries.contains_key(key) {
            let window = self.window;
            entries.retain(|_, stamps| {
                prune(stamps, now, window);
                !stamps.is_empty()
            });
        }
        entries.entry(key.to_owned()).or_default().push_back(now);
    }
}

/// 去掉窗口外的记录；`VecDeque` 按时间递增，从头弹出即可。
fn prune(stamps: &mut VecDeque<Instant>, now: Instant, window: Duration) {
    while let Some(front) = stamps.front() {
        if now.saturating_duration_since(*front) >= window {
            stamps.pop_front();
        } else {
            break;
        }
    }
}

/// 取锁；持锁代码不会 panic，若真的被毒化则取回内部数据继续用——
/// 限速器丢状态会让爆破防护失效，比直接 panic 更糟。
fn lock(
    entries: &Mutex<HashMap<String, VecDeque<Instant>>>,
) -> std::sync::MutexGuard<'_, HashMap<String, VecDeque<Instant>>> {
    entries.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::SlidingWindowLimiter;

    fn limiter() -> SlidingWindowLimiter {
        SlidingWindowLimiter::new(Duration::from_secs(300))
    }

    #[test]
    fn given_zero_limit_when_blocked_then_never_limits() {
        let limiter = limiter();
        for _ in 0..100 {
            limiter.record("alice");
        }

        assert_eq!(limiter.blocked_for("alice", 0), None, "0 = 不限");
    }

    #[test]
    fn given_failures_below_limit_when_blocked_then_not_limited() {
        let limiter = limiter();
        limiter.record("alice");
        limiter.record("alice");

        assert_eq!(limiter.blocked_for("alice", 3), None);
        assert_eq!(limiter.blocked_for("bob", 3), None, "不同 key 互不影响");
    }

    #[test]
    fn given_failures_at_limit_when_blocked_then_retry_after_until_window_expires() {
        let now = Instant::now();
        let limiter = limiter();
        limiter.record_at("alice", now);
        limiter.record_at("alice", now + Duration::from_secs(30));
        limiter.record_at("alice", now + Duration::from_secs(60));

        let wait = limiter
            .blocked_for_at("alice", 3, now + Duration::from_secs(90))
            .expect("达到上限应给出等待时间");
        // 最早一条记录在 now，窗口 300s，因此还要等 210s。
        assert_eq!(wait, Duration::from_secs(210));

        // 窗口滑过后计数归零：不再限速。
        assert_eq!(limiter.blocked_for_at("alice", 3, now + Duration::from_secs(301)), None);
    }

    #[test]
    fn given_successful_reset_when_blocked_then_cleared() {
        let limiter = limiter();
        for _ in 0..3 {
            limiter.record("alice");
        }
        assert!(limiter.blocked_for("alice", 3).is_some());

        limiter.reset("alice");

        assert_eq!(limiter.blocked_for("alice", 3), None, "成功登录后计数清零");
    }

    #[test]
    fn given_expired_records_when_record_then_pruned_so_memory_stays_bounded() {
        let now = Instant::now();
        let limiter = limiter();
        limiter.record_at("alice", now);
        limiter.record_at("alice", now + Duration::from_secs(400));

        assert_eq!(
            limiter.blocked_for_at("alice", 2, now + Duration::from_secs(400)),
            None,
            "过期记录应在查询时被丢弃，只剩未过期的那一条"
        );
        assert!(
            limiter.blocked_for_at("alice", 1, now + Duration::from_secs(400)).is_some(),
            "未过期的那一条仍应计数"
        );
    }
}
