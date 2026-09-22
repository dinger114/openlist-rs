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

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) store: Arc<Store>,
    pub(crate) drivers: Arc<Mutex<HashMap<String, Arc<Driver>>>>,
    pub(crate) auth: Option<Arc<AuthCfg>>,
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
    pub(crate) fn new(
        dir: &str,
        web_user: Option<String>,
        web_pass: Option<String>,
    ) -> Self {
        let store = Arc::new(Store::load(dir));
        // 鉴权：--web-user/env 提供用户名即启用；密码缺省则随机生成打印
        let env_user = std::env::var("OPENLIST_WEB_USER")
            .ok()
            .filter(|s| !s.is_empty());
        let env_pass = std::env::var("OPENLIST_WEB_PASS")
            .ok()
            .filter(|s| !s.is_empty());
        let auth =
            match (web_user.or(env_user), web_pass.or(env_pass)) {
                (Some(user), pass) => {
                    let pass = pass.unwrap_or_else(|| {
                        let generated = format!(
                            "{}{}",
                            uuid::Uuid::new_v4().simple(),
                            uuid::Uuid::new_v4().simple()
                        )[..16]
                            .to_string();
                        println!("未指定 --web-pass，已自动生成面板密码: {generated}");
                        generated
                    });
                    Some(Arc::new(AuthCfg { user, pass }))
                }
                _ => {
                    println!(
                        "未设置面板账号（--web-user/--web-pass 或 OPENLIST_WEB_USER/OPENLIST_WEB_PASS），面板免登录访问"
                    );
                    None
                }
            };
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
