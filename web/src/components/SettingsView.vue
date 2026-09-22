<template>
  <div class="page settings-page">
    <h2 class="settings-title">设置</h2>

    <section class="card panel">
      <div class="panel-head">
        <Icon name="user" :size="18" />
        <h2>面板账号</h2>
      </div>
      <div class="panel-body">
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
          <button class="btn" :disabled="saving" @click="save">
            <span v-if="saving" class="spin loader-sm"></span>
            {{ saving ? '保存中…' : '保存' }}
          </button>
        </div>
        <p class="hint-text">保存后所有登录会话将失效，需用新的账号密码重新登录。</p>
      </div>
    </section>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import Icon from './Icon.vue'

const emit = defineEmits(['saved'])

const username = ref('')
const password = ref('')
const confirm = ref('')
const error = ref('')
const saving = ref(false)

onMounted(async () => {
  try {
    const r = await fetch('/api/web/user')
    if (r.ok) {
      const b = await r.json()
      username.value = b.username || ''
    }
  } catch (_) {}
})

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
.settings-page {
  max-width: 560px;
  margin: 0 auto;
  padding: 4px 20px 60px;
}
.settings-title {
  font-size: 18px;
  font-weight: 700;
  color: var(--ol-text);
  margin: 0 0 16px;
}
.settings-actions {
  display: flex;
  justify-content: flex-end;
}
.loader-sm {
  width: 14px;
  height: 14px;
  border: 2px solid var(--ol-border-strong);
  border-top-color: var(--ol-primary);
  border-radius: 50%;
}
</style>
