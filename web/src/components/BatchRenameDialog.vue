<template>
  <div class="dlg-mask" @click.self="$emit('close')">
    <div class="dlg card">
      <div class="dlg-head">
        <span class="dlg-title">重命名 {{ entries.length }} 项</span>
        <button class="btn-icon btn-ghost" title="关闭（Esc）" @click="$emit('close')">
          <Icon name="close" :size="16" />
        </button>
      </div>

      <div class="dlg-body">
        <!-- 查找替换（字面替换，不做正则）：一次性写进下面的输入框，还能逐行微调 -->
        <div class="rn-find">
          <input v-model="find" class="input" placeholder="查找" />
          <input v-model="repl" class="input" placeholder="替换为" />
          <button class="btn btn-secondary" :disabled="!find" @click="applyReplace">应用到全部</button>
          <span class="rn-hit">{{ find ? `命中 ${findHit} 项` : '' }}</span>
        </div>

        <div class="rn-list">
          <div v-for="(e, i) in entries" :key="e.key" class="rn-row">
            <span class="rn-old" :title="e.name">{{ e.name }}</span>
            <input v-model="names[i]" class="input" @focus="focusMainName($event, i)" />
          </div>
        </div>

        <div class="rn-foot">
          <span class="rn-err">{{ err }}</span>
          <button class="btn btn-secondary" @click="$emit('close')">取消</button>
          <button class="btn" :disabled="!!err || !changed" @click="submit">重命名</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onBeforeUnmount } from 'vue'
import Icon from './Icon.vue'

const props = defineProps({
  // 选中的条目（含 name / key / is_dir）
  entries: { type: Array, required: true },
  // 每行条目所在目录的全部名字（下标与 entries 对齐），用于查重
  // （搜索结果可能跨目录，所以查重必须按各自目录来，不能用一个总表）
  siblings: { type: Array, default: () => [] }
})
const emit = defineEmits(['close', 'submit'])

const names = ref(props.entries.map((e) => e.name))

const find = ref('')
const repl = ref('')
const findHit = computed(() => (find.value ? names.value.filter((n) => n.includes(find.value)).length : 0))
function applyReplace() {
  if (!find.value) return
  names.value = names.value.map((n) => n.split(find.value).join(repl.value))
}

// 聚焦时默认只选中主名（扩展名不选中，仍可手动改）
function focusMainName(ev, i) {
  const input = ev.target
  const name = names.value[i] || ''
  const dot = name.lastIndexOf('.')
  input.setSelectionRange(0, dot > 0 ? dot : name.length)
}

const err = computed(() => {
  if (names.value.some((n) => !n.trim())) return '名称不能为空'
  if (names.value.some((n) => n.includes('/'))) return '名称不能包含 /'
  if (new Set(names.value.map((n) => n.trim())).size !== names.value.length) return '批内有重名'
  const others = names.value.some((n, i) => {
    const sibs = (props.siblings[i] || []).filter((x) => !props.entries.some((e) => e.name === x))
    return sibs.includes(n.trim())
  })
  if (others) return '与所在目录已有文件重名'
  return ''
})
const changed = computed(() => names.value.some((n, i) => n.trim() !== props.entries[i].name))

function submit() {
  if (err.value || !changed.value) return
  emit('submit', names.value.map((n) => n.trim()))
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
  gap: 10px;
  padding: 14px 16px 16px;
  overflow-y: auto;
}
.rn-find {
  display: flex;
  align-items: center;
  gap: 6px;
}
.rn-find .input {
  flex: 1;
  min-width: 0;
}
.rn-hit {
  font-size: 12px;
  color: var(--ol-text-dim);
  white-space: nowrap;
}
.rn-list {
  display: flex;
  flex-direction: column;
  gap: 6px;
  max-height: 46vh;
  overflow-y: auto;
}
.rn-row {
  display: flex;
  align-items: center;
  gap: 8px;
}
.rn-old {
  width: 42%;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: 12.5px;
  color: var(--ol-text-dim);
}
.rn-row .input {
  flex: 1;
  min-width: 0;
}
.rn-foot {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 8px;
  padding-top: 10px;
  border-top: 1px solid var(--ol-border);
}
.rn-err {
  margin-right: auto;
  font-size: 12px;
  color: var(--ol-danger);
}
</style>
