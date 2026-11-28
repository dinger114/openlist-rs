// 批量任务（服务端后台执行）的前端状态：提交、轮询进度、取消、移除。
//
// 服务端见 src/jobs.rs：POST /api/batch/{move,copy,remove,rename} 立即返回任务 id，
// 真正的执行在后台跑，进度统一从 GET /api/batch/tasks 拉。
//
// 展示口径：面板只显示「本页提交过的任务」和「当前在跑的任务」——服务端最多保留
// 50 条历史，全量拉过来会让任务面板变成日志。
import { ref, computed, onBeforeUnmount } from 'vue'

const TERMINAL = new Set(['succeeded', 'partial', 'canceled'])
const DEFAULT_POLL_MS = 800

export function useBatchJobs({ request, pollMs = DEFAULT_POLL_MS } = {}) {
  if (typeof request !== 'function') throw new Error('useBatchJobs 需要 request 函数')

  const jobs = ref([]) // 服务端任务表（新 -> 旧）
  const mine = ref(new Set()) // 本页提交过的 id
  const hidden = ref(new Set()) // 用户手动清掉的 id

  const handled = new Set() // 已经回调过「完成」的任务 id
  let runningBefore = new Set()
  let onDone = null
  let timer = null

  const visible = computed(() =>
    jobs.value.filter((j) => {
      if (hidden.value.has(j.id)) return false
      return j.state === 'running' || mine.value.has(j.id)
    })
  )
  const running = computed(() => jobs.value.filter((j) => j.state === 'running').length)

  /** 注册「某条任务刚跑到终态」的回调（用来刷新目录/搜索结果） */
  function onFinished(fn) {
    onDone = fn
  }

  function apply(tasks) {
    const nowRunning = new Set(tasks.filter((j) => j.state === 'running').map((j) => j.id))
    for (const j of tasks) {
      if (!TERMINAL.has(j.state) || handled.has(j.id)) continue
      // 只对本页提交过、或本页见过它在跑的任务回调，避免历史任务刷屏
      if (!mine.value.has(j.id) && !runningBefore.has(j.id)) continue
      handled.add(j.id)
      onDone?.(j)
    }
    runningBefore = nowRunning
    jobs.value = tasks
    syncPolling()
  }

  async function refresh() {
    try {
      const b = await request('/api/batch/tasks')
      apply(b.tasks || [])
    } catch {
      /* 拉失败不清表，下一轮再试 */
    }
  }

  function syncPolling() {
    const need = jobs.value.some((j) => j.state === 'running')
    if (need && !timer) {
      timer = setInterval(refresh, pollMs)
    } else if (!need && timer) {
      clearInterval(timer)
      timer = null
    }
  }

  /** 提交一条批量任务，返回任务 id；参数错误会抛出（HTTP 4xx） */
  async function submit(kind, payload) {
    const b = await request(`/api/batch/${kind}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    })
    if (b?.id) mine.value = new Set([...mine.value, b.id])
    await refresh()
    syncPolling()
    return b?.id
  }

  async function cancel(id) {
    try {
      await request(`/api/batch/tasks/${encodeURIComponent(id)}/cancel`, { method: 'POST' })
    } finally {
      await refresh()
    }
  }

  async function dismiss(id) {
    hidden.value = new Set([...hidden.value, id])
    try {
      await request(`/api/batch/tasks/${encodeURIComponent(id)}`, { method: 'DELETE' })
      if (mine.value.has(id)) {
        const next = new Set(mine.value)
        next.delete(id)
        mine.value = next
      }
    } finally {
      await refresh()
    }
  }

  onBeforeUnmount(() => {
    if (timer) {
      clearInterval(timer)
      timer = null
    }
  })

  return { jobs: visible, running, submit, cancel, dismiss, refresh, onFinished }
}