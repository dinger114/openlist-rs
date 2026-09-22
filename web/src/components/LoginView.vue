<template>
  <div class="login-screen">
    <!-- Official OpenList-style background: solid blue + corner gradient blobs -->
    <div class="login-bg" :class="{ dark: isDark }">
      <div class="corner corner-top" aria-hidden="true">
        <svg height="1337" width="1337" viewBox="0 0 1337 1337">
          <defs>
            <path
              id="path-1"
              fill-rule="evenodd"
              d="M1337,668.5 C1337,1037.455193874239 1037.455193874239,1337 668.5,1337 C523.6725684305388,1337 337,1236 370.50000000000006,1094 C434.03835568300906,824.6732385973953 6.906089672974592e-14,892.6277623047779 0,668.5000000000001 C0,299.5448061257611 299.5448061257609,1.1368683772161603e-13 668.4999999999999,0 C1037.455193874239,0 1337,299.544806125761 1337,668.5Z"
            />
            <linearGradient id="lg-top" x1="0.79" y1="0.62" x2="0.21" y2="0.86">
              <stop offset="0" stop-color="#28aff0" stop-opacity="1" />
              <stop offset="1" stop-color="#120fc4" stop-opacity="1" />
            </linearGradient>
          </defs>
          <use href="#path-1" fill="url(#lg-top)" />
        </svg>
      </div>
      <div class="corner corner-bottom" aria-hidden="true">
        <svg height="896" width="968" viewBox="0 0 968 896">
          <defs>
            <path
              id="path-2"
              fill-rule="evenodd"
              d="M896,448 C1142.6325445712241,465.5747656464056 695.2579309733121,896 448,896 C200.74206902668806,896 5.684341886080802e-14,695.2579309733121 0,448.0000000000001 C0,200.74206902668806 200.74206902668791,5.684341886080802e-14 447.99999999999994,0 C695.2579309733121,0 475,418 896,448Z"
            />
            <linearGradient id="lg-bottom" x1="0.5" y1="0" x2="0.5" y2="1">
              <stop offset="0" stop-color="#28aff0" stop-opacity="1" />
              <stop offset="1" stop-color="#120fc4" stop-opacity="1" />
            </linearGradient>
          </defs>
          <use href="#path-2" fill="url(#lg-bottom)" />
        </svg>
      </div>
    </div>

    <div class="login-card">
      <!-- 标题行：Logo + 标题（对齐官方 login/index.tsx） -->
      <div class="brand-row">
        <Logo :size="46" class="brand-logo" />
        <h1 class="brand-title">登录到 OpenList</h1>
      </div>

      <input
        class="input"
        :value="form.username"
        @input="$emit('update:form', { ...form, username: $event.target.value })"
        autocomplete="username"
        placeholder="请输入用户名"
        name="username"
      />
      <input
        class="input"
        type="password"
        :value="form.password"
        @input="$emit('update:form', { ...form, password: $event.target.value })"
        autocomplete="current-password"
        placeholder="请输入密码"
        name="password"
        @keydown.enter="$emit('login')"
      />

      <!-- 记住账号 / 忘记密码 -->
      <div class="form-row">
        <label class="remember">
          <input v-model="remember" type="checkbox" class="checkbox" />
          <span>记住账号</span>
        </label>
        <a class="forget" href="https://openlistteam.github.io/docs/" target="_blank" rel="noopener">
          忘记密码?
        </a>
      </div>

      <div v-if="error" class="alert alert-error">{{ error }}</div>

      <!-- 清除 / 登录 -->
      <div class="btn-row">
        <button
          type="button"
          class="btn-pair btn-clear"
          @click="clear"
        >
          清除
        </button>
        <button type="button" class="btn-pair btn-login" :disabled="loading" @click="$emit('login')">
          <span v-if="loading" class="spin loader"></span>
          {{ loading ? '登录中…' : '登录' }}
        </button>
      </div>

      <!-- 以游客身份浏览 -->
      <button type="button" class="btn-pair btn-guest" @click="$emit('guest')">
        以游客身份浏览
      </button>

      <!-- 底部：主题切换 -->
      <div class="login-extra">
        <button type="button" class="extra-btn" title="切换主题" @click="toggleTheme">
          <Icon :name="isDark ? 'sun' : 'moon'" :size="20" />
        </button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, watch } from 'vue'
import Icon from './Icon.vue'
import Logo from './Logo.vue'

defineProps({
  form: { type: Object, required: true },
  error: { type: String, default: '' },
  loading: { type: Boolean, default: false }
})
const emit = defineEmits(['login', 'update:form', 'guest'])

const isDark = ref(false)
const remember = ref(localStorage.getItem('ol-remember') === 'true')

// 勾选记住账号：与官方一致，把用户名/密码存 localStorage，下次自动填充
watch(remember, (v) => {
  localStorage.setItem('ol-remember', String(v))
  if (!v) {
    localStorage.removeItem('ol-user')
    localStorage.removeItem('ol-pwd')
  }
})

function clear() {
  emit('update:form', { username: '', password: '' })
  localStorage.removeItem('ol-user')
  localStorage.removeItem('ol-pwd')
}

function applyTheme(dark) {
  isDark.value = dark
  document.documentElement.classList.toggle('dark', dark)
  try {
    localStorage.setItem('ol-theme', dark ? 'dark' : 'light')
  } catch (_) {}
}

function toggleTheme() {
  applyTheme(!isDark.value)
}

onMounted(() => {
  // 回填记住的账号
  if (remember.value) {
    const u = localStorage.getItem('ol-user')
    const p = localStorage.getItem('ol-pwd')
    if (u || p) emit('update:form', { username: u || '', password: p || '' })
  }
  try {
    const saved = localStorage.getItem('ol-theme')
    if (saved === 'dark') applyTheme(true)
    else if (saved === 'light') applyTheme(false)
    else applyTheme(window.matchMedia('(prefers-color-scheme: dark)').matches)
  } catch (_) {
    applyTheme(false)
  }
})

// 登录成功后由 App 清空；这里负责在输入时同步保存（勾选状态下）
defineExpose({
  saveRemember(username, password) {
    if (!remember.value) return
    if (username) localStorage.setItem('ol-user', username)
    else localStorage.removeItem('ol-user')
    if (password) localStorage.setItem('ol-pwd', password)
    else localStorage.removeItem('ol-pwd')
  }
})
</script>

<style scoped>
.login-screen {
  position: fixed;
  inset: 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  overflow: hidden;
  z-index: 200;
}

.login-bg {
  position: absolute;
  inset: 0;
  z-index: 0;
  background: #a9c6ff;
  overflow: hidden;
}
.login-bg.dark {
  background: #062b74;
}

.corner {
  position: absolute;
  pointer-events: none;
  line-height: 0;
}
.corner svg {
  display: block;
}
.corner-top {
  right: -100px;
  top: -1170px;
}
.corner-bottom {
  left: -100px;
  bottom: -760px;
}
@media (min-width: 640px) {
  .corner-top {
    right: -300px;
    top: -900px;
  }
  .corner-bottom {
    left: -200px;
    bottom: -400px;
  }
}

/* 卡片：w 364 / p 24 / rounded xl / spacing 16（对齐官方 VStack） */
.login-card {
  position: relative;
  z-index: 1;
  width: 364px;
  max-width: 90%;
  background: var(--ol-panel);
  border-radius: 14px;
  box-shadow: 0 8px 32px rgba(18, 15, 196, 0.12);
  padding: 24px;
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.brand-row {
  display: flex;
  align-items: center;
  justify-content: space-around;
  gap: 8px;
  margin-bottom: 2px;
}
.brand-logo {
  --ol-logo-hole: var(--ol-panel);
}
.brand-title {
  margin: 0;
  font-size: 24px;
  font-weight: 600;
  color: #0091ff;
  letter-spacing: 0.2px;
  white-space: nowrap;
}

.login-card .input {
  width: 100%;
  height: 40px;
  padding: 0 12px;
  border: 1px solid var(--ol-border-strong);
  border-radius: 6px;
  background: var(--ol-panel);
  color: var(--ol-text);
  font-size: 14px;
  outline: none;
  transition: border-color 0.15s ease, box-shadow 0.15s ease;
}
.login-card .input:focus {
  border-color: #0091ff;
  box-shadow: 0 0 0 3px rgba(0, 145, 255, 0.15);
}
.login-card .input::placeholder {
  color: var(--ol-text-faint);
}

.form-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 4px;
  font-size: 13px;
  margin-top: -4px;
}
.remember {
  display: flex;
  align-items: center;
  gap: 7px;
  color: var(--ol-text-dim);
  cursor: pointer;
  user-select: none;
}
.checkbox {
  width: 15px;
  height: 15px;
  accent-color: #0091ff;
  cursor: pointer;
}
.forget {
  color: var(--ol-text-dim);
}
.forget:hover {
  color: #0091ff;
  text-decoration: none;
}

/* 按钮行：两个等宽按钮，配色取自官方截图（subtle 蓝） */
.btn-row {
  display: flex;
  gap: 8px;
}
.btn-pair {
  flex: 1;
  height: 38px;
  border: none;
  border-radius: 6px;
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  transition: filter 0.15s ease;
  white-space: nowrap;
}
.btn-pair:hover {
  filter: brightness(0.97);
}
.btn-pair:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}
.btn-clear {
  background: #d8f3f6;
  color: #0c7792;
}
.btn-login {
  background: #e1f0ff;
  color: #006adc;
}
.btn-guest {
  width: 100%;
  margin-top: -4px;
  background: #ede9fe;
  color: #5746af;
}
html.dark .btn-clear {
  background: #12414a;
  color: #7edce8;
}
html.dark .btn-login {
  background: #142c47;
  color: #6cb8ff;
}
html.dark .btn-guest {
  background: #2a2444;
  color: #b4a4f5;
}

.loader {
  width: 14px;
  height: 14px;
  border: 2px solid rgba(0, 106, 220, 0.35);
  border-top-color: #006adc;
  border-radius: 50%;
  display: inline-block;
  animation: spin 0.7s linear infinite;
}
@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}

.login-extra {
  display: flex;
  justify-content: space-evenly;
  align-items: center;
  color: var(--ol-text-dim);
  padding-top: 2px;
}
.extra-btn {
  width: 36px;
  height: 36px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: transparent;
  border: none;
  border-radius: 8px;
  color: var(--ol-text-dim);
  cursor: pointer;
  transition: color 0.15s ease;
}
.extra-btn:hover {
  color: var(--ol-text);
}
</style>
