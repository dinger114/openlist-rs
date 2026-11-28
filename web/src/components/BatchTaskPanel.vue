<template>
  <div v-if="uploads.length || jobs.length" class="task-panel card">
    <div class="task-head">
      <span>任务</span>
      <button
        v-if="uploads.length"
        class="btn-icon btn-ghost"
        title="清除已完成的上传"
        @click="$emit('clear-uploads')"
      >
        <Icon name="close" :size="14" />
      </button>
    </div>

    <template v-if="jobs.length">
      <div class="task-section">批量操作</div>
      <div v-for="j in jobs" :key="j.id" class="task-item">
        <div class="task-name" :title="j.label">
          <Icon :name="iconOf(j.kind)" :size="14" />
          <span class="task-label">{{ j.label }}</span>
          <span class="task-count">{{ j.done }}/{{ j.total }}</span>
          <button
            v-if="j.state === 'running'"
            class="btn-icon btn-ghost task-x"
            title="取消（做完当前项后停）"
            @click="$emit('cancel-job', j.id)"
          >
            <Icon name="close" :size="13" />
          </button>
          <button
            v-else
            class="btn-icon btn-ghost task-x"
            title="从任务列表移除"
            @click="$emit('dismiss-job', j.id)"
          >
            <Icon name="close" :size="13" />
          </button>
        </div>
        <div class="task-bar">
          <div
            class="task-bar-fill"
            :class="stateClass(j)"
            :style="{ width: pct(j) + '%' }"
          ></div>
        </div>
        <div class="task-meta">
          <span v-if="j.state === 'running'" class="task-phase">
            {{ j.current ? `正在处理 ${j.current}` : '准备中…' }}
          </span>
          <span v-else-if="j.state === 'succeeded'" class="task-ok">已完成</span>
          <span v-else-if="j.state === 'canceled'" class="task-dim">
            已取消（{{ j.done }}/{{ j.total }}）
          </span>
          <span v-else class="task-bad">完成 {{ j.done }} 项，其中 {{ j.failed }} 项失败</span>
          <span v-if="j.errors.length" class="task-err" :title="j.errors.join('\n')">
            · {{ j.errors[0] }}
          </span>
        </div>
      </div>
    </template>

    <template v-if="uploads.length">
      <div class="task-section">上传</div>
      <div v-for="(t, i) in uploads" :key="i" class="task-item">
        <div class="task-name" :title="t.relPath">
          <Icon :name="t.status === 'error' ? 'alert' : 'upload'" :size="14" />
          <span class="task-label">{{ t.relPath }}</span>
        </div>
        <div class="task-bar">
          <div
            class="task-bar-fill"
            :class="{ done: t.status === 'done', fail: t.status === 'error' }"
            :style="{ width: uploadPct(t) + '%' }"
          ></div>
        </div>
        <div class="task-meta">
          {{ t.status === 'error' ? t.error : `${fmtSize(t.loaded)} / ${fmtSize(t.size)}` }}
        </div>
      </div>
    </template>
  </div>
</template>

<script setup>
import Icon from './Icon.vue'

// 纯展示组件：任务数据都由 App.vue 持有（上传进度在前端，批量任务进度在服务端）
const props = defineProps({
  uploads: { type: Array, default: () => [] },
  jobs: { type: Array, default: () => [] }
})
defineEmits(['clear-uploads', 'cancel-job', 'dismiss-job'])

const KIND_ICON = { move: 'move', copy: 'copy', remove: 'trash', rename: 'edit' }

function iconOf(kind) {
  return KIND_ICON[kind] || 'upload'
}

function pct(j) {
  if (j.state === 'succeeded') return 100
  if (!j.total) return 0
  const raw = Math.round((j.done / j.total) * 100)
  // 大批量（几十项以上）前几项四舍五入就是 0%，进度条会看起来「没动」→ 至少给 2%
  return j.state === 'running' ? Math.max(2, raw) : raw
}

function stateClass(j) {
  if (j.state === 'succeeded') return 'done'
  if (j.state === 'partial') return 'fail'
  if (j.state === 'canceled') return 'canceled'
  return ''
}

function fmtSize(n) {
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  let v = n
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${units[i]}`
}

function uploadPct(t) {
  if (t.status === 'done') return 100
  if (!t.size) return t.status === 'uploading' ? 5 : 100
  return Math.min(99, Math.round((t.loaded / t.size) * 100))
}
</script>

<style scoped>
.task-panel {
  position: fixed;
  right: 28px;
  bottom: 96px;
  z-index: 90;
  width: min(360px, calc(100vw - 40px));
  max-height: 46vh;
  overflow: auto;
  padding: 10px 12px;
}
.task-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  font-weight: 600;
  font-size: 13.5px;
  margin-bottom: 4px;
}
.task-section {
  margin-top: 6px;
  color: var(--ol-text-dim);
  font-size: 11.5px;
}
.task-item {
  padding: 6px 0;
  border-bottom: 1px solid var(--ol-border);
}
.task-item:last-child {
  border-bottom: none;
}
.task-name {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12.5px;
  color: var(--ol-text);
  white-space: nowrap;
  overflow: hidden;
}
.task-label {
  flex: 1;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
}
.task-count {
  font-variant-numeric: tabular-nums;
  color: var(--ol-text-dim);
  font-size: 11.5px;
  flex-shrink: 0;
}
.task-x {
  flex-shrink: 0;
  padding: 2px;
}
.task-bar {
  height: 4px;
  margin: 5px 0 4px;
  background: var(--ol-bg);
  border-radius: 999px;
  overflow: hidden;
}
.task-bar-fill {
  height: 100%;
  background: var(--ol-primary);
  border-radius: 999px;
  transition: width 0.2s ease;
}
.task-bar-fill.done {
  background: #2fa96c;
}
.task-bar-fill.fail {
  background: #e5484d;
}
.task-bar-fill.canceled {
  background: var(--ol-text-faint);
}
.task-meta {
  font-size: 11px;
  color: var(--ol-text-dim);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.task-phase {
  color: var(--ol-primary);
}
.task-ok {
  color: #2fa96c;
}
.task-bad {
  color: var(--ol-danger);
}
.task-dim {
  color: var(--ol-text-faint);
}
.task-err {
  color: var(--ol-danger);
}
@media (max-width: 640px) {
  .task-panel {
    right: 12px;
    left: 12px;
    width: auto;
    bottom: 84px;
  }
}
</style>