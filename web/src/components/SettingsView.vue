<template>
  <div class="page settings-page">
    <!-- 页头：标题（对齐存储管理页） -->
    <div class="settings-head">
      <h2 class="settings-title">设置</h2>
    </div>

    <!-- 面板账号卡片（结构对齐"已添加存储"卡片） -->
    <section class="card panel">
      <div class="panel-head">
        <Icon name="user" :size="18" />
        <h2>面板账号</h2>
      </div>
      <div class="panel-body">
        <div class="settings-form">
          <div class="field">
            <label>登录用户名</label>
            <input
              class="input"
              v-model="username"
              autocomplete="username"
              placeholder="面板登录用户名"
            />
          </div>
          <div class="field">
            <label>新密码</label>
            <input
              class="input"
              type="password"
              v-model="password"
              autocomplete="new-password"
              placeholder="留空则不修改密码"
            />
          </div>
          <div class="field">
            <label>确认新密码</label>
            <input
              class="input"
              type="password"
              v-model="confirm"
              autocomplete="new-password"
              placeholder="再次输入新密码"
              @keydown.enter="save"
            />
          </div>

          <div v-if="error" class="alert alert-error">{{ error }}</div>

          <div class="settings-actions">
            <button class="btn add-btn" :disabled="saving" @click="save">
              <span v-if="saving" class="spin loader-sm"></span>
              {{ saving ? '保存中…' : '保存' }}
            </button>
          </div>
          <p class="hint-text">保存后所有登录会话将失效，需用新的账号密码重新登录。</p>
        </div>
      </div>
    </section>

    <!-- API 令牌（OpenList 式静态凭据，供 ostrm / AList 客户端 / WebDAV 使用） -->
    <ApiTokenCard />

    <!-- WebDAV 入口（地址 / 认证 / 挂载方式） -->
    <WebdavCard :username="username" />

    <!-- 配置备份与恢复 -->
    <section class="card panel">
      <div class="panel-head">
        <Icon name="download" :size="18" />
        <h2>配置备份</h2>
      </div>
      <div class="panel-body">
        <p class="hint-text" style="margin-bottom: 16px">
          导出当前配置（含所有存储账号、面板账号、API 令牌）；导入备份可恢复到本实例。
          可选密码加密：加密后的备份文件即使泄露也无法直接读取。
        </p>

        <!-- 导出 -->
        <div class="backup-row">
          <div class="field">
            <label>导出密码（可选）</label>
            <input
              class="input"
              type="password"
              v-model="exportPassword"
              placeholder="留空则不加密"
            />
          </div>
          <div class="settings-actions" style="margin-top: 0">
            <button class="btn add-btn" :disabled="exporting" @click="exportBackup">
              <span v-if="exporting" class="spin loader-sm"></span>
              {{ exporting ? '导出中…' : '导出备份' }}
            </button>
          </div>
        </div>

        <!-- 导入 -->
        <div class="backup-row" style="margin-top: 20px">
          <div class="field">
            <label>导入备份文件</label>
            <div class="file-picker">
              <input
                ref="fileInput"
                type="file"
                accept=".olbk"
                @change="onFileSelect"
              />
              <button type="button" class="file-picker-btn" @click="$refs.fileInput.click()">
                <Icon name="upload" :size="14" />
                <span>选择文件</span>
              </button>
              <span class="file-picker-name" :class="{ empty: !selectedFile }">
                {{ selectedFile ? `${selectedFile.name} (${formatSize(selectedFile.size)})` : '未选择文件' }}
              </span>
            </div>
          </div>
          <div class="field">
            <label>解密密码（若备份已加密）</label>
            <input
              class="input"
              type="password"
              v-model="importPassword"
              placeholder="备份已加密时必填"
            />
          </div>
          <div class="settings-actions" style="margin-top: 0">
            <button
              class="btn add-btn"
              :disabled="!selectedFile || importing"
              @click="importBackup"
            >
              <span v-if="importing" class="spin loader-sm"></span>
              {{ importing ? '恢复中…' : '恢复配置' }}
            </button>
          </div>
        </div>

        <div v-if="importError" class="alert alert-error" style="margin-top: 16px">
          {{ importError }}
        </div>
        <div v-if="importOk" class="alert alert-ok" style="margin-top: 16px">
          配置已恢复（{{ importAccountCount }} 个账号），请重新登录。
        </div>
      </div>
    </section>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import Icon from './Icon.vue'
import ApiTokenCard from './ApiTokenCard.vue'
import WebdavCard from './WebdavCard.vue'

const emit = defineEmits(['saved'])

const username = ref('')
const password = ref('')
const confirm = ref('')
const error = ref('')
const saving = ref(false)

// 备份
const exportPassword = ref('')
const exporting = ref(false)
const selectedFile = ref(null)
const importPassword = ref('')
const importing = ref(false)
const importError = ref('')
const importOk = ref(false)
const importAccountCount = ref(0)

function formatSize(bytes) {
  if (bytes < 1024) return bytes + ' B'
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB'
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB'
}

onMounted(async () => {
  try {
    const r = await fetch('/api/web/user')
    if (r.ok) {
      const b = await r.json()
      username.value = b.username || ''
    }
  } catch (_) {}
})

async function exportBackup() {
  exporting.value = true
  try {
    const r = await fetch('/api/web/backup/create', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: exportPassword.value || undefined })
    })
    if (!r.ok) {
      const b = await r.json().catch(() => ({}))
      throw new Error(b.error || '导出失败')
    }
    const blob = await r.blob()
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = ''
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
    exportPassword.value = ''
  } catch (e) {
    importError.value = e.message
  } finally {
    exporting.value = false
  }
}

function onFileSelect(e) {
  importError.value = ''
  importOk.value = false
  selectedFile.value = e.target.files[0] || null
}

async function importBackup() {
  if (!selectedFile.value) return
  importing.value = true
  importError.value = ''
  importOk.value = false
  try {
    const fd = new FormData()
    fd.append('file', selectedFile.value)
    if (importPassword.value) {
      fd.append('password', importPassword.value)
    }
    const r = await fetch('/api/web/backup/restore', {
      method: 'POST',
      body: fd
    })
    const b = await r.json().catch(() => ({}))
    if (!r.ok) throw new Error(b.error || '恢复失败')
    importAccountCount.value = b.accounts || 0
    importOk.value = true
    selectedFile.value = null
    importPassword.value = ''
    // 服务端已清空会话，触发父组件切到登录
    emit('saved')
  } catch (e) {
    importError.value = e.message
  } finally {
    importing.value = false
  }
}

async function save() {
  error.value = ''
  const user = username.value.trim()
  const pwd = password.value
  if (!user) {
    error.value = '用户名不能为空'
    return
  }
  if (pwd && pwd !== confirm.value) {
    error.value = '两次输入的密码不一致'
    return
  }
  saving.value = true
  try {
    const r = await fetch('/api/web/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: user, password: pwd || undefined })
    })
    const b = await r.json().catch(() => ({}))
    if (!r.ok) throw new Error(b.error || '保存失败')
    // 服务端已清空全部会话，回到登录页用新凭据重新登录
    password.value = ''
    confirm.value = ''
    emit('saved')
  } catch (e) {
    error.value = e.message
  } finally {
    saving.value = false
  }
}
</script>

<style scoped>
/* 页面容器：与存储管理页同宽（accounts-page 同款） */
.settings-page {
  max-width: 980px;
  margin: 0 auto;
  padding: 4px 20px 60px;
}

/* 页头：标题 */
.settings-head {
  display: flex;
  align-items: center;
  margin-bottom: 16px;
}
.settings-title {
  font-size: 18px;
  font-weight: 700;
  color: var(--ol-text);
  margin: 0;
}

/* 卡片：panel-head / panel-body 与存储管理页同款样式 */
.panel {
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
  padding: 24px 20px;
}

/* 表单：限制最大宽度并放宽间距，避免文字过度紧凑 */
.settings-form {
  max-width: 520px;
}
.settings-form .field {
  margin-bottom: 20px;
}
.settings-form .field label {
  display: block;
  margin-bottom: 8px;
  font-size: 13px;
  color: var(--ol-text-dim);
  font-weight: 500;
}
.settings-actions {
  display: flex;
  justify-content: flex-start;
  margin: 24px 0 12px;
}
.add-btn {
  display: flex;
  align-items: center;
  gap: 5px;
  min-width: 88px;
}
.loader-sm {
  width: 14px;
  height: 14px;
  border: 2px solid var(--ol-border-strong);
  border-top-color: var(--ol-primary);
  border-radius: 50%;
}
.settings-form .hint-text {
  margin: 0;
}

/* 备份区：字段垂直堆叠，避免卡片过宽 */
.backup-row {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

/* 文件选择器：把原生 file input 隐藏，用按钮 + 文件名显示替代 */
.file-picker {
  position: relative;
  display: flex;
  align-items: center;
  gap: 8px;
}

.file-picker input[type="file"] {
  position: absolute;
  inset: 0;
  opacity: 0;
  cursor: pointer;
  z-index: 1;
}

.file-picker-btn {
  display: flex;
  align-items: center;
  gap: 5px;
  flex-shrink: 0;
  height: 38px;
  padding: 0 14px;
  background: var(--ol-panel);
  border: 1px solid var(--ol-border-strong);
  color: var(--ol-text);
  border-radius: var(--ol-radius-sm);
  font-size: 14px;
  cursor: pointer;
  transition: border-color 0.15s ease, box-shadow 0.15s ease;
}

.file-picker-btn:hover {
  border-color: var(--ol-primary);
  box-shadow: 0 0 0 2px color-mix(in srgb, var(--ol-primary) 18%, transparent);
}

.file-picker-name {
  font-size: 13px;
  color: var(--ol-text-secondary);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  min-width: 0;
}

.file-picker-name.empty {
  color: var(--ol-text-muted);
  font-style: italic;
}
</style>
