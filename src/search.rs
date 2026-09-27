//! 目录内搜索：从当前目录按需 BFS 遍历子目录，筛出文件名命中的条目。
//!
//! 上游 Go 版是索引制（`internal/search` + db/bleve/meilisearch，要预先给账号建全量索引，
//! `mode=none` 就整个不可用），本仓不移植那套框架：这里按需遍历 + 复用 `ListCache`
//! （10 分钟列表缓存，重复搜同一片区域几乎零成本），并设扫描目录数/结果数/并发三个上限。
//!
//! 代价：搜一次最多 = 「范围内的目录数」次列表请求（远程站会慢），所以
//! - 深度默认 1（当前目录 + 其直接子目录，够筛出 A/B/C）
//! - 单目录读取失败不中断整体搜索，只计入 `failed_dirs` 让前端提示

use crate::config::Entry;
use crate::state::AppState;
use futures_util::stream::{self, StreamExt};
use serde_json::{json, Value};

/// 扫描目录数上限：远程站每个子目录一次列表请求，必须设顶
pub(crate) const SEARCH_MAX_DIRS: usize = 300;
/// 结果条数上限
pub(crate) const SEARCH_MAX_HITS: usize = 500;
/// 并发列表数：再高容易撞网盘限速（如 123 的 700ms 闸门）
const SEARCH_CONCURRENCY: usize = 4;
/// 深度兜底（前端传「全部」时的上界，真正拦住的是 SEARCH_MAX_DIRS）
pub(crate) const SEARCH_MAX_DEPTH: usize = 32;

pub(crate) struct SearchOut {
    /// 命中条目：Entry 原字段 + `path` / `parent_path` / `parent_fid`
    pub(crate) hits: Vec<Value>,
    pub(crate) scanned_dirs: usize,
    /// 扫描目录数或结果数触顶（结果可能不全）
    pub(crate) truncated: bool,
    /// 读取失败的目录数（不中断整体搜索）
    pub(crate) failed_dirs: usize,
}

/// 命中判定：不区分大小写的包含；空关键词不算命中
pub(crate) fn hit_name(q: &str, name: &str) -> bool {
    let q = q.trim();
    if q.is_empty() {
        return false;
    }
    name.to_lowercase().contains(&q.to_lowercase())
}

/// 扫一层目录：产出命中条目与需要继续下钻的子目录 `(fid, 虚拟路径)`
pub(crate) fn scan_dir(
    dir_fid: &str,
    dir_path: &str,
    entries: &[Entry],
    q: &str,
    include_dirs: bool,
) -> (Vec<Value>, Vec<(String, String)>) {
    let mut hits = Vec::new();
    let mut subdirs = Vec::new();
    for e in entries {
        let path = format!("{dir_path}/{}", e.name);
        // 子目录无论是否命中都要入队（下层可能还有命中项）
        if e.is_dir {
            subdirs.push((e.fid.clone(), path.clone()));
        }
        if !hit_name(q, &e.name) || (e.is_dir && !include_dirs) {
            continue;
        }
        let mut v = serde_json::to_value(e).unwrap_or_else(|_| json!({}));
        if let Some(o) = v.as_object_mut() {
            o.insert("path".into(), json!(path));
            o.insert("parent_path".into(), json!(dir_path));
            o.insert("parent_fid".into(), json!(dir_fid));
        }
        hits.push(v);
    }
    (hits, subdirs)
}

/// 按需 BFS 搜索。level 0 = 根目录本身，`depth=1` 表示再往下钻一层
/// （因此能筛出「A 的子目录 B 里的 C」）。
#[allow(clippy::too_many_arguments)]
pub(crate) async fn search_tree(
    st: &AppState,
    acc_id: &str,
    root_fid: &str,
    root_path: &str,
    q: &str,
    depth: usize,
    include_dirs: bool,
    limit: usize,
    max_dirs: usize,
) -> Result<SearchOut, String> {
    let depth = depth.min(SEARCH_MAX_DEPTH);
    let mut hits: Vec<Value> = Vec::new();
    let mut scanned = 0usize;
    let mut failed = 0usize;
    let mut truncated = false;
    let mut level: Vec<(String, String)> = vec![(root_fid.to_string(), root_path.to_string())];
    let mut lvl = 0usize;

    while !level.is_empty() {
        // 扫描上限：本层只取还扫得动的目录数，多余的丢掉并标记「可能不全」
        let remain = max_dirs.saturating_sub(scanned);
        if remain == 0 {
            truncated = true;
            break;
        }
        let mut batch: Vec<(String, String)> = std::mem::take(&mut level);
        if batch.len() > remain {
            batch.truncate(remain);
            truncated = true;
        }
        scanned += batch.len();

        let listed: Vec<(Result<Vec<Entry>, String>, String, String)> = stream::iter(batch)
            .map(|(fid, path)| async move {
                let r = st.list_dir_cached(acc_id, &fid, false).await;
                (r, fid, path)
            })
            .buffer_unordered(SEARCH_CONCURRENCY)
            .collect()
            .await;

        let mut next: Vec<(String, String)> = Vec::new();
        for (r, fid, path) in listed {
            match r {
                Ok(entries) => {
                    let (h, subs) = scan_dir(&fid, &path, &entries, q, include_dirs);
                    if lvl < depth {
                        next.extend(subs);
                    }
                    hits.extend(h);
                }
                Err(_) => failed += 1,
            }
        }

        if hits.len() > limit {
            hits.truncate(limit);
            truncated = true;
        }
        if truncated || lvl >= depth {
            break;
        }
        level = next;
        lvl += 1;
    }

    // 按虚拟路径排序，结果稳定（同一目录内即按名字）
    hits.sort_by(|a, b| {
        let pa = a.get("path").and_then(|v| v.as_str()).unwrap_or("");
        let pb = b.get("path").and_then(|v| v.as_str()).unwrap_or("");
        pa.cmp(pb)
    });

    Ok(SearchOut {
        hits,
        scanned_dirs: scanned,
        truncated,
        failed_dirs: failed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Account, Credential};

    fn tmp_base(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("olrs-search-{}-{}", std::process::id(), tag));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// 造 A/{C0.txt,其它.txt,B1/{C1.txt,D/E.txt},B2/C2.txt} 并注册 local 账号
    fn fixture(tag: &str) -> AppState {
        let base = tmp_base(tag);
        let root = base.join("A");
        std::fs::create_dir_all(root.join("B1").join("D")).unwrap();
        std::fs::create_dir_all(root.join("B2")).unwrap();
        for (p, c) in [
            ("C0.txt", "0"),
            ("其它.txt", "o"),
            ("B1/C1.txt", "1"),
            ("B1/D/E.txt", "e"),
            ("B2/C2.txt", "2"),
        ] {
            std::fs::write(root.join(p), c).unwrap();
        }
        let st = AppState::new(&base.join("data").to_string_lossy());
        let acc = Account {
            id: "acc-search".into(),
            name: "搜索盘".into(),
            cred: Credential::Local {
                root_path: root.to_string_lossy().to_string(),
            },
            root_fid: "0".into(),
            server_proxy: false,
            enabled: true,
        };
        st.store.data.lock().unwrap().accounts.push(acc);
        st
    }

    fn paths(out: &SearchOut) -> Vec<String> {
        out.hits
            .iter()
            .map(|h| h["path"].as_str().unwrap_or("").to_string())
            .collect()
    }

    #[test]
    fn hit_name_is_case_insensitive_and_skips_blank() {
        assert!(hit_name("c", "C1.TXT"));
        assert!(hit_name("C1", "c1.txt"));
        assert!(hit_name("中文", "某 中文 名.md"));
        assert!(!hit_name("", "a.txt"));
        assert!(!hit_name("   ", "a.txt"));
        assert!(!hit_name("z", "a.txt"));
    }

    /// 深度 1 = 当前目录 + 直接子目录：A/B/C 能筛出，A/B/D/E 不能
    #[tokio::test]
    async fn depth1_scans_root_and_one_level_down() {
        let st = fixture("depth1");
        let out = search_tree(
            &st,
            "acc-search",
            "0",
            "/搜索盘",
            "C",
            1,
            false,
            SEARCH_MAX_HITS,
            SEARCH_MAX_DIRS,
        )
        .await
        .unwrap();
        let p = paths(&out);
        assert_eq!(
            p,
            vec![
                "/搜索盘/B1/C1.txt".to_string(),
                "/搜索盘/B2/C2.txt".to_string(),
                "/搜索盘/C0.txt".to_string(),
            ],
            "深度 1 不该把 B1/D/E.txt 算进来"
        );
        assert_eq!(out.scanned_dirs, 3, "扫了 A、B1、B2");
        assert!(!out.truncated);
        assert_eq!(out.failed_dirs, 0);

        let hit = out
            .hits
            .iter()
            .find(|h| h["path"] == "/搜索盘/B1/C1.txt")
            .expect("命中 B1/C1.txt");
        assert_eq!(hit["name"], "C1.txt");
        assert_eq!(hit["parent_path"], "/搜索盘/B1");
        assert_eq!(hit["is_dir"], false);
        assert!(hit["parent_fid"].as_str().unwrap().ends_with("B1"));
    }

    /// 深度 0 = 只搜当前目录自己
    #[tokio::test]
    async fn depth0_only_root() {
        let st = fixture("depth0");
        let out = search_tree(
            &st,
            "acc-search",
            "0",
            "/搜索盘",
            "C",
            0,
            false,
            SEARCH_MAX_HITS,
            SEARCH_MAX_DIRS,
        )
        .await
        .unwrap();
        assert_eq!(paths(&out), vec!["/搜索盘/C0.txt".to_string()]);
        assert_eq!(out.scanned_dirs, 1);
    }

    /// 深度 2 才够到 B1/D/E.txt
    #[tokio::test]
    async fn depth2_reaches_second_level() {
        let st = fixture("depth2");
        let out = search_tree(
            &st,
            "acc-search",
            "0",
            "/搜索盘",
            "E.txt",
            2,
            false,
            SEARCH_MAX_HITS,
            SEARCH_MAX_DIRS,
        )
        .await
        .unwrap();
        assert_eq!(paths(&out), vec!["/搜索盘/B1/D/E.txt".to_string()]);
        assert_eq!(out.scanned_dirs, 4, "A、B1、B2、D");
    }

    /// scope=all 时文件夹也进结果；默认只出文件
    #[tokio::test]
    async fn include_dirs_switch() {
        let st = fixture("dirs");
        let only_files = search_tree(
            &st,
            "acc-search",
            "0",
            "/搜索盘",
            "B",
            1,
            false,
            SEARCH_MAX_HITS,
            SEARCH_MAX_DIRS,
        )
        .await
        .unwrap();
        assert!(paths(&only_files).is_empty(), "默认不返回文件夹");

        let with_dirs = search_tree(
            &st,
            "acc-search",
            "0",
            "/搜索盘",
            "B",
            1,
            true,
            SEARCH_MAX_HITS,
            SEARCH_MAX_DIRS,
        )
        .await
        .unwrap();
        assert_eq!(
            paths(&with_dirs),
            vec!["/搜索盘/B1".to_string(), "/搜索盘/B2".to_string()]
        );
        assert_eq!(with_dirs.hits[0]["is_dir"], true);
    }

    /// 扫描目录数触顶 -> truncated，且不多扫
    #[tokio::test]
    async fn dirs_cap_truncates() {
        let st = fixture("cap");
        let out = search_tree(
            &st,
            "acc-search",
            "0",
            "/搜索盘",
            "C",
            1,
            false,
            SEARCH_MAX_HITS,
            1,
        )
        .await
        .unwrap();
        assert_eq!(out.scanned_dirs, 1);
        assert!(out.truncated);
        assert_eq!(paths(&out), vec!["/搜索盘/C0.txt".to_string()]);
    }

    /// 结果数触顶 -> 截断到 limit
    #[tokio::test]
    async fn hits_cap_truncates() {
        let st = fixture("hitcap");
        let out = search_tree(
            &st,
            "acc-search",
            "0",
            "/搜索盘",
            "C",
            1,
            false,
            2,
            SEARCH_MAX_DIRS,
        )
        .await
        .unwrap();
        assert_eq!(out.hits.len(), 2);
        assert!(out.truncated);
    }

    /// 不存在的账号/根目录：列目录失败 -> 计入 failed_dirs，不 panic
    #[tokio::test]
    async fn missing_root_counts_as_failed_dir() {
        let st = fixture("failed");
        let out = search_tree(
            &st,
            "acc-search",
            "/不存在的目录",
            "/搜索盘",
            "C",
            1,
            false,
            SEARCH_MAX_HITS,
            SEARCH_MAX_DIRS,
        )
        .await
        .unwrap();
        assert!(out.hits.is_empty());
        assert_eq!(out.failed_dirs, 1);
        assert_eq!(out.scanned_dirs, 1);
    }
}
