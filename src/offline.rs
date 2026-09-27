//! 原生离线下载任务表（内存态）
//!
//! 供应商侧（如哈拉云）自带离线任务：本机只负责提交、轮询状态、把结果映射成
//! 面板能看的一条记录。任务不落盘 —— 与 `upload_progress` 同构：重启即清空，
//! 但供应商侧的任务仍在跑（面板会看不到它）。
//!
//! 面板接口见 `src/api.rs` 的 `offline_*` 系列。

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::state::AppState;

/// 本机任务状态（4 态，够面板用）
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum TaskState {
    Running,
    Succeeded,
    Failed,
    Removed,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct OfflineTask {
    pub(crate) id: String,
    pub(crate) tool: String,
    pub(crate) account_id: String,
    /// 目标目录的 fid（哈拉云目录的 fid 就是供应商 path）—— 完成后按它失效列表缓存
    pub(crate) dst_fid: String,
    /// 目标目录的面板展示路径（仅用于 UI）
    pub(crate) dst_path: String,
    pub(crate) url: String,
    /// 供应商任务 identity
    pub(crate) gid: String,
    pub(crate) state: TaskState,
    pub(crate) status_text: String,
    pub(crate) progress: f64,
    pub(crate) total_bytes: i64,
    pub(crate) error: String,
    pub(crate) created_at: i64,
    pub(crate) end_at: Option<i64>,
}

impl OfflineTask {
    pub(crate) fn new(
        tool: String,
        account_id: String,
        dst_fid: String,
        dst_path: String,
        url: String,
    ) -> Self {
        OfflineTask {
            id: uuid::Uuid::new_v4().to_string(),
            tool,
            account_id,
            dst_fid,
            dst_path,
            url,
            gid: String::new(),
            state: TaskState::Running,
            status_text: "已提交".into(),
            progress: 0.0,
            total_bytes: 0,
            error: String::new(),
            created_at: now_unix(),
            end_at: None,
        }
    }

    /// 用供应商状态刷新本机任务。终态一经写入不再被覆盖
    /// （迟到的 list 响应会把失败任务改回「下载中」，必须挡住）
    pub(crate) fn apply_status(&mut self, s: &crate::drivers::halalcloud_open::OfflineTaskStatus) {
        if matches!(
            self.state,
            TaskState::Succeeded | TaskState::Failed | TaskState::Removed
        ) {
            return;
        }
        self.status_text = crate::drivers::halalcloud_open::offline_status_text(s);
        if s.total_bytes > 0 {
            self.total_bytes = s.total_bytes;
        }
        if s.status < 0 {
            self.state = TaskState::Failed;
            self.error = if s.message.trim().is_empty() && s.code != 0 {
                format!("离线任务失败 (status {}, code {})", s.status, s.code)
            } else if s.message.trim().is_empty() {
                format!("离线任务失败 (status {})", s.status)
            } else {
                s.message.trim().to_string()
            };
            self.end_at = Some(now_unix());
            return;
        }
        self.progress = s.progress.clamp(0, 100) as f64;
        if s.status == crate::drivers::halalcloud_open::OFFLINE_STATUS_COMPLETE {
            self.state = TaskState::Succeeded;
            self.progress = 100.0;
            self.end_at = Some(now_unix());
        }
    }
}

/// 完成后要失效的列表缓存 key（与 `ListCache` 的 key 约定一致）
pub(crate) fn dst_cache_key(t: &OfflineTask) -> String {
    format!("{}:{}", t.account_id, t.dst_fid)
}

/// 当前 unix 秒
pub(crate) fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 终态任务最多保留多少条（轮询表不能无界增长）
pub(crate) const MAX_KEPT_TASKS: usize = 200;
/// 供应商任务列表缓存 TTL：面板多个任务共用一次请求
const PROVIDER_LIST_TTL: Duration = Duration::from_secs(10);
/// 轮询间隔
const POLL_INTERVAL: Duration = Duration::from_secs(3);
/// 单次拉供应商任务列表的上限（对方卡住时不能拖死轮询）
const PROVIDER_LIST_TIMEOUT: Duration = Duration::from_secs(30);
/// 取消任务时删记录的上限
pub(crate) const PROVIDER_DELETE_TIMEOUT: Duration = Duration::from_secs(15);

type ProviderList = Vec<crate::drivers::halalcloud_open::OfflineTaskStatus>;

pub(crate) struct OfflineManager {
    tasks: Mutex<HashMap<String, OfflineTask>>,
    provider_list: Mutex<HashMap<String, (Instant, ProviderList)>>,
}

impl OfflineManager {
    pub(crate) fn new() -> Self {
        OfflineManager {
            tasks: Mutex::new(HashMap::new()),
            provider_list: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn insert(&self, t: OfflineTask) {
        let mut tasks = self.tasks.lock().unwrap();
        tasks.insert(t.id.clone(), t);
        prune(&mut tasks);
    }

    pub(crate) fn get(&self, id: &str) -> Option<OfflineTask> {
        self.tasks.lock().unwrap().get(id).cloned()
    }

    /// 全部任务：进行中在前，同组按创建时间倒序
    pub(crate) fn list(&self) -> Vec<OfflineTask> {
        let mut v: Vec<OfflineTask> = self.tasks.lock().unwrap().values().cloned().collect();
        v.sort_by(|a, b| {
            (a.state != TaskState::Running)
                .cmp(&(b.state != TaskState::Running))
                .then_with(|| b.created_at.cmp(&a.created_at))
        });
        v
    }

    pub(crate) fn running(&self) -> Vec<OfflineTask> {
        self.list()
            .into_iter()
            .filter(|t| t.state == TaskState::Running)
            .collect()
    }

    pub(crate) fn remove(&self, id: &str) -> Option<OfflineTask> {
        self.tasks.lock().unwrap().remove(id)
    }

    /// 轮询回写：找到同 gid 的任务就刷新状态，返回「本次刚转终态」的那条
    pub(crate) fn apply(
        &self,
        gid: &str,
        s: &crate::drivers::halalcloud_open::OfflineTaskStatus,
    ) -> Option<OfflineTask> {
        let mut tasks = self.tasks.lock().unwrap();
        let t = tasks
            .values_mut()
            .find(|t| !t.gid.is_empty() && t.gid == gid)?;
        let was_running = t.state == TaskState::Running;
        t.apply_status(s);
        if was_running && t.state != TaskState::Running {
            return Some(t.clone());
        }
        None
    }

    /// 某账号的进行中任务全部判失败（账号不可用/被删时）
    pub(crate) fn fail_account_tasks(&self, account: &str, reason: &str) {
        let mut tasks = self.tasks.lock().unwrap();
        for t in tasks.values_mut() {
            if t.account_id == account && t.state == TaskState::Running {
                t.state = TaskState::Failed;
                t.error = reason.to_string();
                t.status_text = "失败".into();
                t.end_at = Some(now_unix());
            }
        }
    }

    pub(crate) fn set_provider_list_at(&self, account: &str, at: Instant, list: ProviderList) {
        self.provider_list
            .lock()
            .unwrap()
            .insert(account.to_string(), (at, list));
    }

    /// TTL 内返回缓存的供应商任务列表（时间由参数传入，便于单测）
    pub(crate) fn provider_list(&self, account: &str, now: Instant) -> Option<ProviderList> {
        self.provider_list
            .lock()
            .unwrap()
            .get(account)
            .filter(|(t, _)| now.saturating_duration_since(*t) < PROVIDER_LIST_TTL)
            .map(|(_, l)| l.clone())
    }

    /// 本轮该给哪些账号拉任务列表：有进行中任务的账号，且 10 秒内还没拉过
    pub(crate) fn accounts_to_poll(&self, now: Instant) -> Vec<String> {
        let mut accs: Vec<String> = self
            .running()
            .into_iter()
            .map(|t| t.account_id)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        accs.retain(|a| self.provider_list(a, now).is_none());
        accs
    }
}

impl Default for OfflineManager {
    fn default() -> Self {
        Self::new()
    }
}

/// 终态任务超上限时，淘汰 end_at 最旧的那些
fn prune(tasks: &mut HashMap<String, OfflineTask>) {
    let terminal = |t: &OfflineTask| t.state != TaskState::Running;
    if tasks.values().filter(|t| terminal(t)).count() <= MAX_KEPT_TASKS {
        return;
    }
    let mut done: Vec<(String, i64)> = tasks
        .values()
        .filter(|t| terminal(t))
        .map(|t| (t.id.clone(), t.end_at.unwrap_or(t.created_at)))
        .collect();
    done.sort_by_key(|(_, at)| *at);
    for (id, _) in done.iter().take(done.len() - MAX_KEPT_TASKS) {
        tasks.remove(id);
    }
}

/// 每 3 秒一次：给「有进行中任务」的账号拉一次供应商任务列表，回写状态并在终态
/// 精确失效目标目录的列表缓存
pub(crate) fn spawn_poller(st: AppState) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(POLL_INTERVAL);
        loop {
            tick.tick().await;
            let now = Instant::now();
            for acc in st.offline.accounts_to_poll(now) {
                let driver = match st.get_driver(&acc).await {
                    Ok(d) => d,
                    Err(e) => {
                        eprintln!("离线任务轮询：取驱动失败 {acc}: {e}");
                        // 账号被删/崩溃时别每 3 秒重试一次，直接标失败
                        st.offline
                            .fail_account_tasks(&acc, "存储不可用，无法查询离线任务进度");
                        continue;
                    }
                };
                // 供应商侧可能卡住：给一次列表请求加上限
                let list = match tokio::time::timeout(PROVIDER_LIST_TIMEOUT, driver.offline_list())
                    .await
                {
                    Ok(Ok(l)) => l,
                    Ok(Err(e)) => {
                        eprintln!("离线任务轮询：拉列表失败 {acc}: {e}");
                        continue; // 单次失败不判死，下一轮再试
                    }
                    Err(_) => {
                        eprintln!("离线任务轮询：拉列表超时 {acc}");
                        continue;
                    }
                };
                st.offline.set_provider_list_at(&acc, now, list.clone());
                for s in &list {
                    if let Some(done) = st.offline.apply(&s.identity, s) {
                        // 终态：目标目录缓存立刻失效，面板下次刷新就能看到新文件
                        st.list_cache.invalidate_key(&dst_cache_key(&done));
                        if done.state == TaskState::Failed {
                            eprintln!("离线任务失败 {}: {}", done.url, done.error);
                        }
                    }
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drivers::halalcloud_open::OfflineTaskStatus;

    fn status(status: i64, progress: i64, msg: &str, code: i64) -> OfflineTaskStatus {
        OfflineTaskStatus {
            identity: "g1".into(),
            status,
            progress,
            total_bytes: 0,
            name: String::new(),
            message: msg.into(),
            code,
        }
    }

    fn task(tool: &str, acc: &str, gid: &str, dst_fid: &str) -> OfflineTask {
        let mut t = OfflineTask::new(
            tool.into(),
            acc.into(),
            dst_fid.into(),
            "/网盘/下载".into(),
            "https://example.com/a.bin".into(),
        );
        t.gid = gid.into();
        t
    }

    #[test]
    fn apply_status_maps_contract() {
        let mut t = OfflineTask::new(
            "HalalCloudOpen".into(),
            "acc-1".into(),
            "0".into(),
            "/网盘/下载".into(),
            "https://example.com/a.mkv".into(),
        );
        assert_eq!(t.state, TaskState::Running);

        // 下载中：状态文案来自供应商
        t.apply_status(&status(50, 42, "", 0));
        assert_eq!(t.state, TaskState::Running);
        assert_eq!(t.progress, 42.0);
        assert_eq!(t.status_text, "下载中 42%");

        // 完成：进度钉 100，记结束时间
        t.apply_status(&status(1000, 99, "", 0));
        assert_eq!(t.state, TaskState::Succeeded);
        assert_eq!(t.progress, 100.0);
        assert!(t.end_at.is_some());

        // 失败：错误文案优先取 message，缺了要自带状态码
        let mut f = OfflineTask::new("t".into(), "a".into(), "0".into(), "/p".into(), "u".into());
        f.apply_status(&status(-1, 0, "链接已失效", 0));
        assert_eq!(f.state, TaskState::Failed);
        assert_eq!(f.error, "链接已失效");
        let mut f2 = OfflineTask::new("t".into(), "a".into(), "0".into(), "/p".into(), "u".into());
        f2.apply_status(&status(-7, 0, "", 12));
        assert!(f2.error.contains("status -7") && f2.error.contains("code 12"));

        // 终态不被后续状态覆盖（避免迟到的一次 list 把 failed 又变回 running）
        f.apply_status(&status(50, 80, "", 0));
        assert_eq!(f.state, TaskState::Failed);
    }

    #[test]
    fn dst_cache_key_is_account_scoped() {
        let t = task("t", "acc-1", "g1", "0");
        assert_eq!(dst_cache_key(&t), "acc-1:0");
    }

    #[test]
    fn manager_add_get_remove_and_prune() {
        let m = OfflineManager::new();
        let t = task("HalalCloudOpen", "acc", "g1", "0");
        let id = t.id.clone();
        m.insert(t);
        assert_eq!(m.get(&id).unwrap().gid, "g1");
        assert_eq!(m.running().len(), 1);

        m.remove(&id);
        assert!(m.get(&id).is_none());

        // 终态任务保留上限：超出后淘汰最旧的
        for i in 0..(MAX_KEPT_TASKS + 5) {
            let mut t = task("t", "acc", &format!("g{i}"), "0");
            t.state = TaskState::Succeeded;
            t.end_at = Some(i as i64);
            t.created_at = i as i64;
            m.insert(t);
        }
        assert!(
            m.list()
                .iter()
                .filter(|t| t.state == TaskState::Succeeded)
                .count()
                <= MAX_KEPT_TASKS
        );
    }

    #[test]
    fn provider_list_cache_respects_ttl() {
        let m = OfflineManager::new();
        let now = Instant::now();
        m.set_provider_list_at("acc", now, vec![]);
        assert!(m.provider_list("acc", now).is_some());
        // TTL 内命中
        assert!(m
            .provider_list("acc", now + Duration::from_secs(5))
            .is_some());
        // 超 TTL 视为未命中
        assert!(m
            .provider_list("acc", now + Duration::from_secs(11))
            .is_none());
    }

    #[test]
    fn accounts_to_poll_dedups_and_skips_fresh_cache() {
        let m = OfflineManager::new();
        let a = task("t", "acc-1", "g1", "0");
        m.insert(a);
        // 同账号多条进行中任务只算一个账号
        let a2 = task("t", "acc-1", "g2", "0");
        m.insert(a2);
        // 终态任务不触发轮询
        let mut b = task("t", "acc-2", "g3", "0");
        b.state = TaskState::Succeeded;
        m.insert(b);

        let now = Instant::now();
        assert_eq!(m.accounts_to_poll(now), vec!["acc-1".to_string()]);
        // 该账号 10 秒内已拉过 → 本轮跳过
        m.set_provider_list_at("acc-1", now, vec![]);
        assert!(m.accounts_to_poll(now + Duration::from_secs(3)).is_empty());
        assert_eq!(m.accounts_to_poll(now + Duration::from_secs(11)).len(), 1);
    }

    #[test]
    fn manager_apply_only_returns_first_terminal_transition() {
        let m = OfflineManager::new();
        let t = task("t", "acc", "g1", "/dst");
        let id = t.id.clone();
        m.insert(t);
        // 未提交过 gid 的任务（gid 空）不会被误匹配
        assert!(m.apply("", &status(1000, 100, "", 0)).is_none());
        assert_eq!(m.get(&id).unwrap().state, TaskState::Running);
        // 首次转终态返回该条
        let done = m
            .apply("g1", &status(1000, 100, "", 0))
            .expect("应返回终态任务");
        assert_eq!(done.id, id);
        // 再拉一次不该重复上报（否则每轮都刷目录）
        assert!(m.apply("g1", &status(1000, 100, "", 0)).is_none());
    }

    #[test]
    fn fail_account_tasks_marks_running_only() {
        let m = OfflineManager::new();
        m.insert(task("t", "acc-1", "g1", "0"));
        let mut done = task("t", "acc-1", "g2", "0");
        done.state = TaskState::Succeeded;
        done.end_at = Some(1);
        m.insert(done);
        m.insert(task("t", "acc-2", "g3", "0"));

        m.fail_account_tasks("acc-1", "存储不可用");
        let l = m.list();
        assert_eq!(
            l.iter().filter(|t| t.state == TaskState::Failed).count(),
            1,
            "只有进行中的那条被判失败"
        );
        assert_eq!(
            l.iter().filter(|t| t.state == TaskState::Succeeded).count(),
            1,
            "终态任务不受影响"
        );
        assert_eq!(
            l.iter()
                .filter(|t| t.account_id == "acc-2" && t.state == TaskState::Running)
                .count(),
            1,
            "别的账号不受影响"
        );
    }
}
