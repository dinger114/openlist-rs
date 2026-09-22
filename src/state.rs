use crate::config::{Entry, Store};
use crate::drivers::Driver;
use std::collections::{HashMap, HashSet};
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
    pub(crate) pass: String,
}

/// 随机 8 位密码（去除易混淆字符的字母 + 数字）
pub(crate) fn random_password() -> String {
    const CHARSET: &[u8] = b"abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..8)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
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
        pass = Some(p);
        changed = true;
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

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) store: Arc<Store>,
    pub(crate) drivers: Arc<Mutex<HashMap<String, Arc<Driver>>>>,
    /// 面板登录凭据（始终启用鉴权； RwLock 支持设置页在线修改）
    pub(crate) auth: Arc<std::sync::RwLock<AuthCfg>>,
    pub(crate) sessions: Arc<Mutex<HashSet<String>>>,
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
        let auth = Arc::new(init_web_auth(&store));
        AppState {
            store,
            drivers: Arc::new(Mutex::new(HashMap::new())),
            auth,
            sessions: Arc::new(Mutex::new(HashSet::new())),
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
}
