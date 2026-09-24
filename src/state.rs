use crate::config::{Entry, Store};
use crate::drivers::Driver;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// 目录列表内存缓存（参考 OpenList dirCache 设计）
///
/// - 纯内存、不落盘，重启即清空
/// - key = "{账号id}:{fid}"，账号 id 为 UUID 不含 ':'，前缀匹配安全
/// - TTL 10 分钟，过期后重新请求网盘
/// - 有条目上限兜底，避免极端场景内存无界增长
pub(crate) struct ListCache {
    map: Mutex<HashMap<String, (Instant, Vec<Entry>)>>,
}

impl ListCache {
    const TTL: Duration = Duration::from_secs(10 * 60);
    const MAX_ENTRIES: usize = 512;

    fn new() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
        }
    }

    /// 命中返回条目副本，过期条目视为不存在
    pub(crate) fn get(&self, key: &str) -> Option<Vec<Entry>> {
        let map = self.map.lock().unwrap();
        map.get(key)
            .filter(|(t, _)| t.elapsed() < Self::TTL)
            .map(|(_, entries)| entries.clone())
    }

    /// 写入缓存；满时先淘汰过期项，仍满则放弃本次写入
    pub(crate) fn set(&self, key: &str, entries: Vec<Entry>) {
        let mut map = self.map.lock().unwrap();
        if map.len() >= Self::MAX_ENTRIES {
            map.retain(|_, (t, _)| t.elapsed() < Self::TTL);
            if map.len() >= Self::MAX_ENTRIES {
                return;
            }
        }
        map.insert(key.to_string(), (Instant::now(), entries));
    }

    /// 删除某账号的全部缓存条目（编辑/删除账号时调用）
    pub(crate) fn invalidate_account(&self, account: &str) {
        let prefix = format!("{account}:");
        self.map
            .lock()
            .unwrap()
            .retain(|k, _| !k.starts_with(&prefix));
    }

    /// 删除单条目录缓存（写操作后精确失效：key = "{账号id}:{fid}"）
    pub(crate) fn invalidate_key(&self, key: &str) {
        self.map.lock().unwrap().remove(key);
    }
}

pub(crate) struct AuthCfg {
    pub(crate) user: String,
    /// argon2id 的 PHC 串（老库的明文会在启动或首次登录时就地升级，见 src/password.rs）
    pub(crate) pass: String,
}

/// 随机 8 位密码（去除易混淆字符的字母 + 数字）
pub(crate) fn random_password() -> String {
    const CHARSET: &[u8] = b"abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    use rand::RngExt;
    let mut rng = rand::rng();
    (0..8)
        .map(|_| CHARSET[rng.random_range(0..CHARSET.len())] as char)
        .collect()
}

/// 面板鉴权初始化：数据库已有账号密码则直接使用（不再打印）；
/// 缺失时初始化为 admin + 随机 8 位密码，打印到终端并持久化（之后启动不再生成）
fn init_web_auth(store: &Store) -> AuthCfg {
    let (user_opt, pass_opt) = {
        let data = store.data.lock().unwrap();
        (data.web_user.clone(), data.web_pass.clone())
    };
    let mut user = user_opt.filter(|s| !s.is_empty());
    let mut pass = pass_opt.filter(|s| !s.is_empty());
    let mut changed = false;
    if user.is_none() {
        println!("面板用户名未设置，已初始化为: admin");
        user = Some("admin".to_string());
        changed = true;
    }
    if pass.is_none() {
        let p = random_password();
        println!("面板密码未设置，已生成随机密码: {p}");
        // 落库的一定是哈希：这里是唯一拿到明文的地方，且明文只打印这一次
        pass = Some(
            crate::password::hash_password(&p)
                .unwrap_or_else(|e| panic!("生成面板密码哈希失败: {e}")),
        );
        changed = true;
    } else if let Some(p) = pass.clone() {
        // 老库（明文存密码）在启动时就地升级，不等首次登录；也是幂等的
        if !crate::password::is_hashed(&p) {
            println!("检测到面板密码为明文存储，已就地升级为 argon2id 哈希");
            pass = Some(
                crate::password::hash_password(&p)
                    .unwrap_or_else(|e| panic!("面板密码哈希失败: {e}")),
            );
            changed = true;
        }
    }
    if changed {
        store
            .update_web_auth(user.clone(), pass.clone())
            .unwrap_or_else(|e| eprintln!("面板账号持久化失败: {e}"));
    }
    AuthCfg {
        user: user.unwrap(),
        pass: pass.unwrap(),
    }
}

/// 会话记录：只存最后使用时间（TTL 与滑动续期见 SESSION_TTL / session_valid_at）
#[derive(Clone, Copy)]
pub(crate) struct SessionInfo {
    pub(crate) last_seen: Instant,
}

/// 会话有效期：与登录 Cookie 的 Max-Age 对齐（7 天），每次校验命中即续期
pub(crate) const SESSION_TTL: Duration = Duration::from_secs(7 * 24 * 3600);

/// 密码哈希允许同时跑几个（argon2 默认参数每次吃 19MiB，必须限并发）
pub(crate) const PASSWORD_CONCURRENCY: usize = 2;

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) store: Arc<Store>,
    pub(crate) drivers: Arc<Mutex<HashMap<String, Arc<Driver>>>>,
    /// 面板登录凭据（始终启用鉴权； RwLock 支持设置页在线修改）
    pub(crate) auth: Arc<std::sync::RwLock<AuthCfg>>,
    /// 会话表：token -> 最后使用时间（TTL 到期即失效，见 SessionInfo）
    pub(crate) sessions: Arc<Mutex<HashMap<String, SessionInfo>>>,
    /// 登录失败限速（按 TCP 对端 IP，内存态，重启即清）
    pub(crate) login_limiter: Arc<Mutex<crate::ratelimit::LoginLimiter>>,
    /// 密码哈希/校验的并发闸门（见 PASSWORD_CONCURRENCY）
    pub(crate) password_gate: Arc<tokio::sync::Semaphore>,
    /// OpenList 兼容层：归一化路径 -> (账号id, Entry)，浏览时逐步注册
    pub(crate) index: Arc<Mutex<HashMap<String, (String, Entry)>>>,
    /// 目录列表内存缓存（TTL 10 分钟）
    pub(crate) list_cache: Arc<ListCache>,
    /// 活跃上传进度：key = 归一化路径，value = 已上传字节数
    /// /api/fs/put、/api/fs/form 写入，完成后移除；/api/fs/put/progress 轮询
    pub(crate) upload_progress: Arc<Mutex<HashMap<String, Arc<std::sync::atomic::AtomicU64>>>>,
}

impl AppState {
    pub(crate) fn new(dir: &str) -> Self {
        let store = Arc::new(Store::load(dir));
        let auth = Arc::new(std::sync::RwLock::new(init_web_auth(&store)));
        AppState {
            store,
            drivers: Arc::new(Mutex::new(HashMap::new())),
            auth,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            login_limiter: Arc::new(Mutex::new(crate::ratelimit::LoginLimiter::new())),
            password_gate: Arc::new(tokio::sync::Semaphore::new(PASSWORD_CONCURRENCY)),
            index: Arc::new(Mutex::new(HashMap::new())),
            list_cache: Arc::new(ListCache::new()),
            upload_progress: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// 按账号 id 惰性构建驱动（首次使用时验证凭据并缓存）
    pub(crate) async fn get_driver(&self, id: &str) -> Result<Arc<Driver>, String> {
        {
            let drivers = self.drivers.lock().unwrap();
            if let Some(d) = drivers.get(id) {
                return Ok(d.clone());
            }
        }
        let cred = {
            let data = self.store.data.lock().unwrap();
            data.accounts
                .iter()
                .find(|a| a.id == id)
                .map(|a| (a.id.clone(), a.cred.clone()))
        };
        let Some((id, cred)) = cred else {
            return Err("账号不存在".into());
        };
        let d = Arc::new(Driver::new(&id, &cred, self.store.clone()).await?);
        self.drivers.lock().unwrap().insert(id, d.clone());
        Ok(d)
    }

    // ---------- 会话（TTL + 滑动续期） ----------

    /// 签发会话：登记当前时刻（token 由调用方生成）
    pub(crate) fn issue_session(&self, token: String) {
        self.sessions.lock().unwrap().insert(
            token,
            SessionInfo {
                last_seen: Instant::now(),
            },
        );
    }

    /// 校验会话是否有效（命中即滑动续期）
    pub(crate) fn session_valid(&self, token: &str) -> bool {
        self.session_valid_at(token, Instant::now())
    }

    /// 带时间参数的会话校验：过期即删除，未过期则刷新最后使用时间。
    /// 时间由参数传入，单测才能钉死行为（不依赖真实时钟）。
    pub(crate) fn session_valid_at(&self, token: &str, now: Instant) -> bool {
        let mut sessions = self.sessions.lock().unwrap();
        match sessions.get_mut(token) {
            Some(info) if now.saturating_duration_since(info.last_seen) < SESSION_TTL => {
                info.last_seen = now;
                true
            }
            Some(_) => {
                sessions.remove(token);
                false
            }
            None => false,
        }
    }

    /// 登出：删除指定会话
    pub(crate) fn drop_session(&self, token: &str) {
        self.sessions.lock().unwrap().remove(token);
    }

    /// 清空全部会话（改密码后调用，所有端需重新登录）
    pub(crate) fn clear_sessions(&self) {
        self.sessions.lock().unwrap().clear();
    }

    /// 清扫过期会话，返回清掉的条数（后台定期调用；校验路径上是惰性过期）
    pub(crate) fn sweep_sessions(&self) -> usize {
        let now = Instant::now();
        let mut sessions = self.sessions.lock().unwrap();
        let before = sessions.len();
        sessions.retain(|_, info| now.saturating_duration_since(info.last_seen) < SESSION_TTL);
        before - sessions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_state(tag: &str) -> AppState {
        let dir = std::env::temp_dir().join(format!("olrs-state-{}-{}", std::process::id(), tag));
        let _ = std::fs::remove_dir_all(&dir);
        AppState::new(&dir.to_string_lossy())
    }

    /// 会话到 TTL 即失效；期间每次使用都会续期
    #[test]
    fn session_expires_after_ttl_and_renews_on_use() {
        let st = temp_state("ttl");
        st.issue_session("tok".into());
        let t0 = Instant::now();
        assert!(st.session_valid_at("tok", t0));
        // 接近 TTL 时仍有效，且这次使用把时钟往后推了（滑动续期）
        let near = t0 + SESSION_TTL - Duration::from_secs(1);
        assert!(st.session_valid_at("tok", near));
        let near2 = near + SESSION_TTL - Duration::from_secs(1);
        assert!(st.session_valid_at("tok", near2));
        // 超过 TTL（从最后一次使用 near2 起算）：失效且被删除
        let expired = near2 + SESSION_TTL + Duration::from_secs(1);
        assert!(!st.session_valid_at("tok", expired));
        assert!(st.sessions.lock().unwrap().is_empty(), "过期会话必须被删除");
        assert!(!st.session_valid("tok"));
    }

    /// 未知 token、登出、改密码清空
    #[test]
    fn unknown_token_logout_and_clear() {
        let st = temp_state("logout");
        assert!(!st.session_valid("nope"));
        st.issue_session("a".into());
        st.issue_session("b".into());
        st.drop_session("a");
        assert!(!st.session_valid("a"));
        assert!(st.session_valid("b"));
        st.clear_sessions();
        assert!(!st.session_valid("b"));
        assert_eq!(st.sessions.lock().unwrap().len(), 0);
    }

    /// 后台清扫只清过期的，未过期的留着
    #[test]
    fn sweep_removes_only_expired() {
        let st = temp_state("sweep");
        st.issue_session("old".into());
        // 把 last_seen 拨到 TTL 之外（系统刚启动、时间轴不够长时跳过）
        let Some(old) = Instant::now().checked_sub(SESSION_TTL + Duration::from_secs(1)) else {
            return;
        };
        {
            let mut sessions = st.sessions.lock().unwrap();
            if let Some(info) = sessions.get_mut("old") {
                info.last_seen = old;
            }
        }
        st.issue_session("new".into());
        assert_eq!(st.sweep_sessions(), 1);
        assert!(st.sessions.lock().unwrap().contains_key("new"));
    }

    /// 老库的明文密码：启动时就地升级成 argon2 哈希，且不影响后续校验
    #[test]
    fn plaintext_password_is_upgraded_at_startup() {
        let dir = std::env::temp_dir().join(format!("olrs-state-upgrade-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let dir_s = dir.to_string_lossy().to_string();
        {
            // 直接往库里塞明文（绕过 update_web_auth 的哈希收口，模拟旧版本写下的数据）
            let store = Store::load(&dir_s);
            store.update_web_auth(Some("admin".into()), None).unwrap();
            {
                let mut data = store.data.lock().unwrap();
                data.web_pass = Some("plain-old-pass".into());
                let snapshot = data.clone();
                drop(data);
                store.save(&snapshot).unwrap();
            }
        }
        let st = AppState::new(&dir_s);
        let stored = st.auth.read().unwrap().pass.clone();
        assert!(
            stored.starts_with("$argon2id$"),
            "启动应把明文升级为哈希: {stored}"
        );
        assert!(crate::password::verify_password(&stored, "plain-old-pass").ok);
        // 库里也必须是哈希（不是只在内存里换了）
        let in_db = st.store.data.lock().unwrap().web_pass.clone().unwrap();
        assert_eq!(in_db, stored);
    }
}
