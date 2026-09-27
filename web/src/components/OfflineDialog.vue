<template>
  <div class="dlg-mask" @click.self="$emit('close')">
    <div class="dlg card">
      <div class="dlg-head">
        <span class="dlg-title">离线下载</span>
        <button class="btn-icon btn-ghost" title="关闭（Esc）" @click="$emit('close')">
          <Icon name="close" :size="16" />
        </button>
      </div>

      <div class="dlg-body">
        <div class="dlg-dest" :title="path">下载到 <b>{{ path }}</b></div>

        <label class="dlg-label" for="offline-tool">下载工具</label>
        <select id="offline-tool" v-model="tool" class="input" :disabled="tools.length <= 1">
          <option v-for="t in tools" :key="t" :value="t">{{ t }}</option>
        </select>

        <label class="dlg-label" for="offline-urls">下载链接（一行一个，http/https）</label>
        <textarea
          id="offline-urls"
          v-model="urls"
          class="input"
          rows="3"
          placeholder="https://example.com/file.mkv"
        />

        <div class="dlg-row">
          <span v-if="!tools.length" class="dlg-hint">当前目录不支持离线下载</span>
          <span v-else-if="err" class="dlg-err">{{ err }}</span>
          <span v-else class="dlg-hint">提交后由网盘服务端抓取，任务直接落进上面这个目录</span>
          <button class="btn" :disabled="!canSubmit || busy" @click="submit">
            {{ busy ? '提交中…' : '提交下载' }}
          </button>
        </div>

        <div class="dlg-list">
          <div class="dlg-list-head">
            任务
            <span v-if="running > 0" class="dlg-running">进行中 {{ running }}</span>
          </div>
          <div v-if="!tasks.length" class="dlg-empty">还没有离线任务</div>
          <div v-for="t in tasks" :key="t.id" class="dlg-item">
            <span class="dlg-dot" :class="`is-${t.state}`"></span>
            <div class="dlg-item-main">
              <div class="dlg-item-url" :title="t.url">{{ t.url }}</div>
              <div class="dlg-item-status">
                {{ t.status_text }}
                <span v-if="t.error" class="dlg-err"> · {{ t.error }}</span>
              </div>
            </div>
            <div class="dlg-item-side">
              <span class="dlg-pct">{{ Math.round(t.progress) }}%</span>
              <button
                v-if="t.state === 'running'"
                class="btn-icon btn-ghost"
                title="取消"
                @click="$emit('cancel', t.id)"
              >
                <Icon name="close" :size="14" />
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, watch, watchEffect, onMounted, onBeforeUnmount } from 'vue'
import Icon from './Icon.vue'

// 纯展示组件：接口调用都在 App.vue（面板唯一一份 api()，401 处理、任务表都在那里）
const props = defineProps({
  path: { type: String, required: true },
  tools: { type: Array, default: () => [] },
  tasks: { type: Array, default: () => [] },
  busy: { type: Boolean, default: false },
  err: { type: String, default: '' },
  // 父级提交成功后自增，用来清空输入框
  resetKey: { type: Number, default: 0 }
})
const emit = defineEmits(['close', 'submit', 'cancel'])

const tool = ref('')
const urls = ref('')

// 只有一个工具时默认选中它（也覆盖父级后来才取到工具列表的情况）
watchEffect(() => {
  if (!tool.value) tool.value = props.tools[0] || ''
})
const canSubmit = computed(() => !!tool.value && urls.value.split('\n').some((u) => u.trim()))
const running = computed(() => props.tasks.filter((t) => t.state === 'running').length)

watch(
  () => props.resetKey,
  () => {
    urls.value = ''
  }
)

function submit() {
  if (!canSubmit.value || props.busy) return
  emit('submit', {
    urls: urls.value
      .split('\n')
      .map((u) => u.trim())
      .filter(Boolean),
    tool: tool.value
  })
}

function onKey(ev) {
  if (ev.key === 'Escape') emit('close')
}
onMounted(() => window.addEventListener('keydown', onKey))
onBeforeUnmount(() => window.removeEventListener('keydown', onKey))
</script>

<style scoped>
.dlg-mask {
  position: fixed;
  inset: 0;
  z-index: 100;
  background: rgba(0, 0, 0, 0.4);
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
}
.dlg {
  width: min(560px, 100%);
  max-height: 82vh;
  display: flex;
  flex-direction: column;
  padding: 0;
  overflow: hidden;
}
.dlg-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  padding: 14px 16px;
  border-bottom: 1px solid var(--ol-border);
}
.dlg-title {
  font-weight: 600;
}
.dlg-body {
  display: flex;
  flex-direction: column;
  gap: 6px;
  padding: 14px 16px 16px;
  overflow-y: auto;
}
.dlg-dest {
  color: var(--ol-text-dim);
  font-size: 12.5px;
  margin-bottom: 4px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.dlg-dest b {
  color: var(--ol-text);
  font-weight: 600;
}
.dlg-label {
  margin-top: 6px;
  color: var(--ol-text-dim);
  font-size: 12.5px;
}
.dlg-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  margin-top: 10px;
}
.dlg-hint {
  color: var(--ol-text-dim);
  font-size: 12.5px;
}
.dlg-err {
  color: var(--ol-danger);
  font-size: 12.5px;
  word-break: break-all;
}
.dlg-list {
  margin-top: 14px;
  padding-top: 12px;
  border-top: 1px solid var(--ol-border);
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.dlg-list-head {
  display: flex;
  align-items: center;
  gap: 8px;
  color: var(--ol-text-dim);
  font-size: 12.5px;
}
.dlg-running {
  color: var(--ol-success);
}
.dlg-empty {
  color: var(--ol-text-faint);
  font-size: 12.5px;
  padding: 6px 0;
}
.dlg-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px 10px;
  border: 1px solid var(--ol-border);
  border-radius: var(--ol-radius-sm);
  background: var(--ol-bg);
}
.dlg-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
  background: var(--ol-text-faint);
}
.dlg-dot.is-running {
  background: var(--ol-primary);
}
.dlg-dot.is-succeeded {
  background: var(--ol-success);
}
.dlg-dot.is-failed {
  background: var(--ol-danger);
}
.dlg-item-main {
  flex: 1;
  min-width: 0;
}
.dlg-item-url {
  font-size: 13px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.dlg-item-status {
  color: var(--ol-text-dim);
  font-size: 12px;
  margin-top: 2px;
}
.dlg-item-side {
  display: flex;
  align-items: center;
  gap: 4px;
  flex-shrink: 0;
}
.dlg-pct {
  color: var(--ol-text-dim);
  font-size: 12px;
  font-variant-numeric: tabular-nums;
}
</style>
