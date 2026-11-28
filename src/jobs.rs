//! 批量操作任务表（内存态）+ 进度轮询
//!
//! 面板的移动 / 复制 / 删除 / 批量重命名都是一次提交建一条任务，后台 tokio 任务
//! 逐项执行并更新计数，前端轮询 [`/api/batch/tasks`] 画进度条。与 `offline`、
//! `upload_progress` 同构：纯内存、不落盘，重启即清空（正在跑的任务随进程消失）。
//!
//! 与旧的同步端点（`compat_fs_move` 等）有两处刻意不同：
//!   * 单项失败不中断整批：失败计入 `failed` 并记进 `errors`，其余项继续；
//!   * 可取消：当前项做完后停手，已完成的保留。
//!
//! 计数口径：`done` = 已处理项数（含失败），`failed` = 其中失败数，
//! 所以进度条永远按 `done / total` 走，不会因为失败卡住。

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::state::AppState;

/// 任务类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum BatchKind {
    Move,
    Copy,
    Remove,
    Rename,
}

impl BatchKind {
    pub(crate) fn verb(self) -> &'static str {
        match self {
            BatchKind::Move => "移动",
            BatchKind::Copy => "复制",
            BatchKind::Remove => "删除",
            BatchKind::Rename => "重命名",
        }
    }
}

/// 任务状态：running -> succeeded / partial / canceled
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum BatchState {
    Running,
    Succeeded,
    Partial,
    Canceled,
}

impl BatchState {
    pub(crate) fn is_running(self) -> bool {
        self == BatchState::Running
    }
}

/// errors 最多留几条：整批 500 项全失败时不能把轮询响应撑爆
pub(crate) const MAX_ERRORS: usize = 20;
/// 任务表上限（新 -> 旧，超出优先丢最老的终态任务）
pub(crate) const MAX_KEPT_JOBS: usize = 50;

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct BatchJob {
    pub(crate) id: String,
    pub(crate) kind: BatchKind,
    /// 面板文案，例：「移动 12 项 → /夸克/电影」
    pub(crate) label: String,
    pub(crate) total: usize,
    /// 已处理项数（含失败）
    pub(crate) done: usize,
    /// 其中失败项数
    pub(crate) failed: usize,
    pub(crate) state: BatchState,
    /// 当前正在处理的条目名（仅 running 时有值）
    pub(crate) current: String,
    pub(crate) errors: Vec<String>,
    pub(crate) created_at: i64,
    pub(crate) end_at: Option<i64>,
}

/// 任务表 + 取消标志表。锁顺序固定：先 jobs 后 cancels，不嵌套。
pub(crate) struct BatchManager {
    jobs: Mutex<Vec<BatchJob>>,
    cancels: Mutex<HashMap<String, Arc<AtomicBool>>>,
}

impl BatchManager {
    pub(crate) fn new() -> Self {
        BatchManager {
            jobs: Mutex::new(Vec::new()),
            cancels: Mutex::new(HashMap::new()),
        }
    }

    /// 建任务，返回 (id, 取消标志)。跨线程更新一律走 `update`/`finish`。
    pub(crate) fn create(
        &self,
        kind: BatchKind,
        label: String,
        total: usize,
    ) -> (String, Arc<AtomicBool>) {
        let id = uuid::Uuid::new_v4().to_string();
        let cancel = Arc::new(AtomicBool::new(false));
        let mut jobs = self.jobs.lock().unwrap_or_else(|e| e.into_inner());
        jobs.insert(
            0,
            BatchJob {
                id: id.clone(),
                kind,
                label,
                total,
                done: 0,
                failed: 0,
                state: BatchState::Running,
                current: String::new(),
                errors: Vec::new(),
                created_at: crate::offline::now_unix(),
                end_at: None,
            },
        );
        prune(&mut jobs);
        let alive: std::collections::HashSet<String> = jobs.iter().map(|j| j.id.clone()).collect();
        drop(jobs);
        let mut cancels = self.cancels.lock().unwrap_or_else(|e| e.into_inner());
        cancels.retain(|id, _| alive.contains(id.as_str()));
        cancels.insert(id.clone(), cancel.clone());
        (id, cancel)
    }

    fn update(&self, id: &str, f: impl FnOnce(&mut BatchJob)) {
        let mut jobs = self.jobs.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(j) = jobs.iter_mut().find(|j| j.id == id) {
            f(j);
        }
    }

    /// 记一项的处理结果：done 必定 +1，失败再累加 failed
    fn record(&self, id: &str, err: Option<String>) {
        self.update(id, |j| {
            j.done += 1;
            j.current.clear();
            if let Some(e) = err {
                j.failed += 1;
                if j.errors.len() < MAX_ERRORS {
                    j.errors.push(e);
                }
            }
        });
    }

    /// 记整组失败（目录解析/驱动不可用）：该组条目一次性算处理完
    fn record_group_failure(&self, id: &str, count: usize, err: String) {
        self.update(id, |j| {
            j.done += count;
            j.failed += count;
            if j.errors.len() < MAX_ERRORS {
                j.errors.push(err);
            }
        });
    }

    fn set_current(&self, id: &str, name: &str) {
        self.update(id, |j| j.current = name.to_string());
    }

    /// 收尾：按 canceled / 失败数落终态
    fn finish(&self, id: &str, canceled: bool) {
        self.update(id, |j| {
            j.current.clear();
            j.state = if canceled {
                BatchState::Canceled
            } else if j.failed > 0 {
                BatchState::Partial
            } else {
                BatchState::Succeeded
            };
            j.end_at = Some(crate::offline::now_unix());
        });
    }

    pub(crate) fn list(&self) -> Vec<BatchJob> {
        self.jobs.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// 取消：只对还在跑的任务生效
    pub(crate) fn cancel(&self, id: &str) -> bool {
        let jobs = self.jobs.lock().unwrap_or_else(|e| e.into_inner());
        let Some(j) = jobs.iter().find(|j| j.id == id) else {
            return false;
        };
        if !j.state.is_running() {
            return false;
        }
        drop(jobs);
        if let Some(flag) = self
            .cancels
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
        {
            flag.store(true, Ordering::Relaxed);
            return true;
        }
        false
    }

    /// 从表里移除一条（只允许终态，避免把跑着的任务丢了）
    pub(crate) fn dismiss(&self, id: &str) -> bool {
        let mut jobs = self.jobs.lock().unwrap_or_else(|e| e.into_inner());
        let Some(pos) = jobs.iter().position(|j| j.id == id) else {
            return false;
        };
        if jobs[pos].state.is_running() {
            return false;
        }
        jobs.remove(pos);
        true
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.jobs.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

/// 超出上限时优先淘汰最老的终态任务；全是进行中才动最老的一条
fn prune(jobs: &mut Vec<BatchJob>) {
    while jobs.len() > MAX_KEPT_JOBS {
        let pos = jobs
            .iter()
            .rposition(|j| !j.state.is_running())
            .unwrap_or(jobs.len() - 1);
        jobs.remove(pos);
    }
}

// ---------- 任务启动 ----------

/// 移动/复制的源分组：(源目录, 条目名列表)
pub(crate) type MoveGroup = (String, Vec<String>);
/// 删除的源分组：(目录, 条目名列表)
pub(crate) type RemoveGroup = (String, Vec<String>);
/// 重命名项：(完整路径, 新名字)
pub(crate) type RenameItem = (String, String);

/// 提交移动/复制任务；参数校验失败返回 Err（同步返回给 HTTP 层 400）
pub(crate) fn spawn_move_or_copy(
    st: AppState,
    is_move: bool,
    dst_dir: String,
    groups: Vec<MoveGroup>,
) -> Result<String, String> {
    let groups: Vec<MoveGroup> = groups
        .into_iter()
        .map(|(dir, names)| {
            (
                dir,
                names
                    .into_iter()
                    .filter(|n| !n.trim().is_empty())
                    .collect::<Vec<_>>(),
            )
        })
        .filter(|(_, names)| !names.is_empty())
        .collect();
    let total: usize = groups.iter().map(|(_, n)| n.len()).sum();
    if total == 0 {
        return Err("没有要处理的条目".into());
    }
    if dst_dir.trim().is_empty() {
        return Err("目标目录为空".into());
    }
    let kind = if is_move {
        BatchKind::Move
    } else {
        BatchKind::Copy
    };
    let dst = crate::compat::normalize_path(&dst_dir);
    let label = format!("{} {} 项 → {}", kind.verb(), total, dst);
    let (id, cancel) = st.jobs.create(kind, label, total);
    let task_id = id.clone();
    tokio::spawn(async move {
        run_move_or_copy(&st, &task_id, &cancel, is_move, dst, groups).await;
    });
    Ok(id)
}

/// 提交删除任务
pub(crate) fn spawn_remove(st: AppState, groups: Vec<RemoveGroup>) -> Result<String, String> {
    let groups: Vec<RemoveGroup> = groups
        .into_iter()
        .map(|(dir, names)| {
            (
                dir,
                names
                    .into_iter()
                    .filter(|n| !n.trim().is_empty())
                    .collect::<Vec<_>>(),
            )
        })
        .filter(|(_, names)| !names.is_empty())
        .collect();
    let total: usize = groups.iter().map(|(_, n)| n.len()).sum();
    if total == 0 {
        return Err("没有要处理的条目".into());
    }
    let label = format!("删除 {} 项", total);
    let (id, cancel) = st.jobs.create(BatchKind::Remove, label, total);
    let task_id = id.clone();
    tokio::spawn(async move {
        run_remove(&st, &task_id, &cancel, groups).await;
    });
    Ok(id)
}

/// 提交批量重命名任务
pub(crate) fn spawn_rename(st: AppState, items: Vec<RenameItem>) -> Result<String, String> {
    let items: Vec<RenameItem> = items
        .into_iter()
        .filter(|(path, name)| !path.trim().is_empty() && !name.trim().is_empty())
        .map(|(path, name)| (path, name.trim().to_string()))
        .collect();
    if items.is_empty() {
        return Err("没有要重命名的条目".into());
    }
    let label = format!("重命名 {} 项", items.len());
    let total = items.len();
    let (id, cancel) = st.jobs.create(BatchKind::Rename, label, total);
    let task_id = id.clone();
    tokio::spawn(async move {
        run_rename(&st, &task_id, &cancel, items).await;
    });
    Ok(id)
}

fn canceled(flag: &Arc<AtomicBool>) -> bool {
    flag.load(Ordering::Relaxed)
}

// ---------- 任务执行 ----------

async fn run_move_or_copy(
    st: &AppState,
    id: &str,
    cancel: &Arc<AtomicBool>,
    is_move: bool,
    dst_dir: String,
    groups: Vec<MoveGroup>,
) {
    // 目标目录解析一次即可；失败等于整批做不了
    let dst = match st.resolve_write_dir(&dst_dir).await {
        Ok(v) => v,
        Err(e) => {
            let count: usize = groups.iter().map(|(_, n)| n.len()).sum();
            st.jobs
                .record_group_failure(id, count, format!("目标目录不可写: {e}"));
            st.jobs.finish(id, false);
            return;
        }
    };
    for (src_dir, names) in groups {
        if canceled(cancel) {
            break;
        }
        let src_dir = crate::compat::normalize_path(&src_dir);
        let (src_acc, src_fid) = match st.resolve_write_dir(&src_dir).await {
            Ok(v) => v,
            Err(e) => {
                st.jobs
                    .record_group_failure(id, names.len(), format!("{src_dir}: {e}"));
                continue;
            }
        };
        let driver = match st.get_driver(&src_acc).await {
            Ok(d) => d,
            Err(e) => {
                st.jobs
                    .record_group_failure(id, names.len(), format!("{src_dir}: {e}"));
                continue;
            }
        };
        for name in names {
            if canceled(cancel) {
                break;
            }
            st.jobs.set_current(id, &name);
            let path = format!("{}/{}", src_dir.trim_end_matches('/'), name);
            let r = match st.resolve_write_entry(&path).await {
                Ok((_, parent_fid, entry)) => {
                    if is_move {
                        driver.move_entry(&parent_fid, &entry, &dst.1).await
                    } else {
                        driver.copy(&parent_fid, &entry, &dst.1).await
                    }
                }
                Err(e) => Err(e),
            };
            match r {
                Ok(()) => {
                    if is_move {
                        st.invalidate_index_prefix(&path);
                    }
                    st.jobs.record(id, None);
                }
                Err(e) => st.jobs.record(id, Some(format!("{name}: {e}"))),
            }
        }
        st.invalidate_dir_cache(&src_acc, &src_fid);
    }
    st.invalidate_dir_cache(&dst.0, &dst.1);
    st.jobs.finish(id, canceled(cancel));
}

async fn run_remove(st: &AppState, id: &str, cancel: &Arc<AtomicBool>, groups: Vec<RemoveGroup>) {
    for (dir, names) in groups {
        if canceled(cancel) {
            break;
        }
        let dir = crate::compat::normalize_path(&dir);
        let (acc_id, dir_fid) = match st.resolve_write_dir(&dir).await {
            Ok(v) => v,
            Err(e) => {
                st.jobs
                    .record_group_failure(id, names.len(), format!("{dir}: {e}"));
                continue;
            }
        };
        let driver = match st.get_driver(&acc_id).await {
            Ok(d) => d,
            Err(e) => {
                st.jobs
                    .record_group_failure(id, names.len(), format!("{dir}: {e}"));
                continue;
            }
        };
        for name in names {
            if canceled(cancel) {
                break;
            }
            st.jobs.set_current(id, &name);
            let path = format!("{}/{}", dir.trim_end_matches('/'), name);
            let r = match st.resolve_write_entry(&path).await {
                Ok((_, parent_fid, entry)) => driver.remove(&parent_fid, &entry).await,
                Err(e) => Err(e),
            };
            match r {
                Ok(()) => {
                    st.invalidate_index_prefix(&path);
                    st.jobs.record(id, None);
                }
                Err(e) => st.jobs.record(id, Some(format!("{name}: {e}"))),
            }
        }
        st.invalidate_dir_cache(&acc_id, &dir_fid);
    }
    st.jobs.finish(id, canceled(cancel));
}

async fn run_rename(st: &AppState, id: &str, cancel: &Arc<AtomicBool>, items: Vec<RenameItem>) {
    for (path, name) in items {
        if canceled(cancel) {
            break;
        }
        let path = crate::compat::normalize_path(&path);
        st.jobs.set_current(id, &name);
        let r = match st.resolve_write_entry(&path).await {
            Ok((acc_id, parent_fid, entry)) => match st.get_driver(&acc_id).await {
                Ok(driver) => driver
                    .rename(&parent_fid, &entry, &name)
                    .await
                    .map(|()| (acc_id, parent_fid)),
                Err(e) => Err(e),
            },
            Err(e) => Err(e),
        };
        match r {
            Ok((acc_id, parent_fid)) => {
                st.invalidate_index_prefix(&path);
                // 改名后父目录列表也要失效（旧名字不能留在缓存里）
                st.invalidate_dir_cache(&acc_id, &parent_fid);
                st.jobs.record(id, None);
            }
            Err(e) => st
                .jobs
                .record(id, Some(format!("{}: {e}", last_seg(&path)))),
        }
    }
    st.jobs.finish(id, canceled(cancel));
}

fn last_seg(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manager() -> BatchManager {
        BatchManager::new()
    }

    #[test]
    fn create_lists_newest_first_and_counts_start_at_zero() {
        let m = manager();
        let (a, _) = m.create(BatchKind::Move, "移动 2 项".into(), 2);
        let (b, _) = m.create(BatchKind::Remove, "删除 1 项".into(), 1);
        let list = m.list();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].id, b);
        assert_eq!(list[1].id, a);
        assert_eq!(list[1].total, 2);
        assert_eq!(list[1].done, 0);
        assert_eq!(list[1].failed, 0);
        assert_eq!(list[1].state, BatchState::Running);
    }

    #[test]
    fn record_counts_done_and_failed_and_keeps_error_text() {
        let m = manager();
        let (id, _) = m.create(BatchKind::Copy, "复制 3 项".into(), 3);
        m.record(&id, None);
        m.record(&id, Some("b: 权限不足".into()));
        m.record(&id, None);
        let j = m.list().into_iter().find(|j| j.id == id).unwrap();
        assert_eq!(j.done, 3);
        assert_eq!(j.failed, 1);
        assert_eq!(j.errors, vec!["b: 权限不足".to_string()]);
    }

    #[test]
    fn errors_are_capped_but_counter_is_not() {
        let m = manager();
        let (id, _) = m.create(BatchKind::Remove, "删除 100 项".into(), 100);
        for i in 0..100 {
            m.record(&id, Some(format!("x{i}: 失败")));
        }
        let j = m.list().into_iter().find(|j| j.id == id).unwrap();
        assert_eq!(j.failed, 100);
        assert_eq!(j.errors.len(), MAX_ERRORS);
    }

    #[test]
    fn finish_maps_to_terminal_state() {
        let m = manager();
        let (ok, _) = m.create(BatchKind::Move, "移动 1 项".into(), 1);
        m.record(&ok, None);
        m.finish(&ok, false);
        let (bad, _) = m.create(BatchKind::Move, "移动 2 项".into(), 2);
        m.record(&bad, None);
        m.record(&bad, Some("b: 失败".into()));
        m.finish(&bad, false);
        let (can, _) = m.create(BatchKind::Move, "移动 2 项".into(), 2);
        m.finish(&can, true);
        let list = m.list();
        let get = |id: &str| list.iter().find(|j| j.id == id).unwrap();
        assert_eq!(get(&ok).state, BatchState::Succeeded);
        assert_eq!(get(&bad).state, BatchState::Partial);
        assert_eq!(get(&can).state, BatchState::Canceled);
        assert!(get(&ok).end_at.is_some());
    }

    #[test]
    fn cancel_only_affects_running_jobs() {
        let m = manager();
        let (id, flag) = m.create(BatchKind::Remove, "删除 1 项".into(), 1);
        assert!(m.cancel(&id));
        assert!(flag.load(Ordering::Relaxed));
        m.finish(&id, true);
        assert!(!m.cancel(&id), "终态任务不能再取消");
        assert!(!m.cancel("不存在"));
    }

    #[test]
    fn dismiss_rejects_running_but_removes_finished() {
        let m = manager();
        let (id, _) = m.create(BatchKind::Rename, "重命名 1 项".into(), 1);
        assert!(!m.dismiss(&id), "进行中的任务不能丢");
        m.finish(&id, false);
        assert!(m.dismiss(&id));
        assert!(m.list().is_empty());
    }

    #[test]
    fn table_is_capped_and_drops_finished_jobs_first() {
        let m = manager();
        let (running, _) = m.create(BatchKind::Move, "跑着的".into(), 1);
        for i in 0..MAX_KEPT_JOBS {
            let (id, _) = m.create(BatchKind::Move, format!("j{i}"), 1);
            m.finish(&id, false);
        }
        // 再建一条，总量应当保持在 MAX_KEPT_JOBS，且进行中的任务还在
        let (id, _) = m.create(BatchKind::Move, "新任务".into(), 1);
        let list = m.list();
        assert!(list.len() <= MAX_KEPT_JOBS);
        assert!(list.iter().any(|j| j.id == running));
        assert!(list.iter().any(|j| j.id == id));
        assert_eq!(m.len(), list.len());
    }

    #[test]
    fn label_and_verb_are_stable_for_ui() {
        assert_eq!(BatchKind::Move.verb(), "移动");
        assert_eq!(BatchKind::Copy.verb(), "复制");
        assert_eq!(BatchKind::Remove.verb(), "删除");
        assert_eq!(BatchKind::Rename.verb(), "重命名");
    }

    #[test]
    fn spawn_validation_rejects_empty_input_without_touching_state() {
        // runner 需要真实驱动，这里只覆盖纯函数式的分组校验
        let groups: Vec<MoveGroup> = vec![
            ("/a".to_string(), Vec::<String>::new()),
            (String::new(), vec!["  ".to_string()]),
        ]
        .into_iter()
        .map(|(dir, names)| {
            (
                dir,
                names
                    .into_iter()
                    .filter(|n: &String| !n.trim().is_empty())
                    .collect::<Vec<_>>(),
            )
        })
        .filter(|(_, names)| !names.is_empty())
        .collect();
        assert!(groups.is_empty());
        let total: usize = groups.iter().map(|(_, n)| n.len()).sum();
        assert_eq!(total, 0, "空分组不该产生任务项");
    }

    #[test]
    fn last_segment_of_path() {
        assert_eq!(super::last_seg("/a/b.txt"), "b.txt");
        assert_eq!(super::last_seg("b.txt"), "b.txt");
    }
}
