<template>
  <section class="card panel">
    <div class="panel-head">
      <Icon name="lock" :size="18" />
      <h2>API 令牌</h2>
    </div>
    <div class="panel-body">
      <div class="tok-field">
        <label>令牌</label>
        <div class="tok-row">
          <code class="tok-code" :class="{ masked: !revealed }">{{ display }}</code>
          <button class="btn btn-ghost btn-sm" @click="revealed = !revealed">
            <Icon name="eye" :size="14" />{{ revealed ? '隐藏' : '显示' }}
          </button>
          <button class="btn btn-ghost btn-sm" @click="copy">
            <Icon name="copy" :size="14" />{{ copied ? '已复制' : '复制' }}
          </button>
          <button class="btn btn-ghost btn-sm tok-reset" :disabled="resetting" @click="reset">
            <Icon name="refresh" :size="14" />{{ resetting ? '重置中…' : '重置' }}
          </button>
        </div>
      </div>

      <p v-if="error" class="alert alert-error">{{ error }}</p>

      <p class="hint-text">
        长期有效的管理员凭据，<b>不过期、重启不失效</b>，用于第三方客户端免登录调用 API。
        请求头写 <code class="tok-code">Authorization: {{ authExample }}</code>
        （带不带 <code class="tok-code">Bearer </code> 前缀都可以）。
      </p>
      <ul class="hint-text tok-usage">
        <li>ostrm：「用户令牌」填这里，服务地址填本站根地址</li>
        <li>AList 协议客户端（NovaTV / TVBox 等）：同上</li>
        <li>WebDAV：用户名任意、密码填令牌，或用 <code class="tok-code">Authorization: Bearer {{ revealed ? token : '（令牌）' }}</code></li>
      </ul>

      <p class="hint-text tok-warn">
        令牌等同于管理员权限：泄漏后请立刻重置，并同步更新 ostrm 等已保存它的客户端。
        重置不影响已登录的面板会话，也不影响已生成的 <code class="tok-code">?sign=</code> 直链。
      </p>

      <div class="tok-divider"></div>

      <div class="tok-field">
        <label>直链签名密钥</label>
        <div class="tok-row">
          <span class="hint-text tok-signhint">
            <code class="tok-code">/d</code> 与 <code class="tok-code">/p</code> 的
            <code class="tok-code">?sign=</code> 由数据目录密钥派生
          </span>
          <button class="btn btn-danger btn-sm" :disabled="signResetting" @click="resetSignKey">
            <Icon name="refresh" :size="14" />{{ signResetting ? '重置中…' : '重置直链签名' }}
          </button>
        </div>
      </div>
      <p class="hint-text">
        重置后所有已发出的直链立即失效（含已生成 STRM 里的 URL），需要重跑生成任务重写；
        已登录的面板会话与已保存的 API 令牌都不受影响。
      </p>
      <p v-if="signNotice" class="alert alert-ok">{{ signNotice }}</p>
    </div>
  </section>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import Icon from './Icon.vue'

const token = ref('')
const revealed = ref(false)
const copied = ref(false)
const resetting = ref(false)
const signResetting = ref(false)
const signNotice = ref('')
const error = ref('')

// 遮罩态只露前缀与末 4 位，足够核对、不够泄漏
const display = computed(() => {
  if (!token.value) return '加载中…'
  if (revealed.value) return token.value
  const head = token.value.slice(0, 9)
  const tail = token.value.slice(-4)
  return `${head}${'•'.repeat(12)}${tail}`
})

// 文档示例里的令牌占位：展开时直接用真值，便于连文档一起复制
const authExample = computed(() => (revealed.value && token.value ? token.value : '（令牌）'))

onMounted(load)

async function load() {
  try {
    const r = await fetch('/api/web/token')
    if (!r.ok) throw new Error('读取失败')
    const b = await r.json()
    token.value = b.token || ''
  } catch (e) {
    error.value = e.message || '读取令牌失败'
  }
}

async function copy() {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(token.value)
    } else {
      // 局域网 HTTP 下 navigator.clipboard 不存在，退化为 execCommand
      const ta = document.createElement('textarea')
      ta.value = token.value
      ta.style.position = 'fixed'
      ta.style.top = '-1000px'
      document.body.appendChild(ta)
      ta.select()
      document.execCommand('copy')
      document.body.removeChild(ta)
    }
    copied.value = true
    setTimeout(() => {
      copied.value = false
    }, 2000)
  } catch (_) {
    error.value = '复制失败，请手动选中复制'
  }
}

async function reset() {
  const ok = window.confirm(
    '确定重置 API 令牌？\n\n旧令牌立即失效，使用它的 ostrm 任务与第三方客户端都会连不上，需要更新为新令牌。'
  )
  if (!ok) return
  error.value = ''
  resetting.value = true
  try {
    const r = await fetch('/api/web/token/reset', { method: 'POST' })
    const b = await r.json().catch(() => ({}))
    if (!r.ok) throw new Error(b.error || '重置失败')
    token.value = b.token || ''
    revealed.value = true
  } catch (e) {
    error.value = e.message
  } finally {
    resetting.value = false
  }
}

/**
 * 重置直链签名盐：让所有已发出的 `?sign=` 链接立即作废。
 * 与重置 API 令牌互不影响 —— 令牌不动直链，直链也不动令牌。
 */
async function resetSignKey() {
  const ok = window.confirm(
    '确定重置直链签名密钥？\n\n所有已发出的 ?sign= 直链会立即失效，' +
      '已经生成好的 STRM 文件里的播放链接也会全部打不开，需要重跑任务重写。'
  )
  if (!ok) return
  error.value = ''
  signNotice.value = ''
  signResetting.value = true
  try {
    const r = await fetch('/api/web/sign-key/reset', { method: 'POST' })
    const b = await r.json().catch(() => ({}))
    if (!r.ok) throw new Error(b.error || '重置失败')
    signNotice.value = '已重置，请重跑生成任务以重写 STRM 里的播放链接。'
  } catch (e) {
    error.value = e.message
  } finally {
    signResetting.value = false
  }
}
</script>

<style scoped>
/* 卡片结构与设置页其他卡片一致（panel-head / panel-body 为各组件自带作用域样式） */
.panel {
  margin-top: 16px;
  overflow: hidden;
}
.panel-head {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 16px 20px;
  border-bottom: 1px solid var(--ol-border);
  color: var(--ol-primary);
}
.panel-head h2 {
  font-size: 15px;
  font-weight: 600;
  color: var(--ol-text);
  margin: 0;
  flex: 1;
}
.panel-body {
  padding: 20px;
}

.tok-field {
  margin-bottom: 14px;
}
.tok-field label {
  display: block;
  margin-bottom: 8px;
  font-size: 13px;
  color: var(--ol-text-dim);
  font-weight: 500;
}
.tok-row {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}
.tok-code {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 12.5px;
  background: var(--ol-bg);
  border: 1px solid var(--ol-border);
  border-radius: var(--ol-radius-sm);
  padding: 5px 9px;
  word-break: break-all;
}
/* 遮罩态用等宽点阵，宽度稳定不跳动 */
.tok-code.masked {
  letter-spacing: 0.5px;
}
.tok-reset {
  color: var(--ol-danger);
}
.tok-usage {
  margin: 0 0 12px;
  padding-left: 18px;
}
.tok-usage li {
  margin-bottom: 4px;
}
.tok-warn {
  color: var(--ol-text-dim);
}

/* 令牌与直链签名两小节之间的分隔 */
.tok-divider {
  height: 1px;
  background: var(--ol-border);
  margin: 18px 0 16px;
}
.tok-signhint {
  flex: 1;
  min-width: 220px;
  margin: 0;
}

/* 重置成功的提示（全局只有 alert-error，成功态在这里补） */
.alert-ok {
  background: var(--ol-primary-light);
  color: var(--ol-primary);
  border: 1px solid var(--ol-primary);
}
</style>
